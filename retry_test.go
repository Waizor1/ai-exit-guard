package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticTimeoutRetry(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		failures, status, calls int
		ok                      bool
	}{
		{"first timeout", 1, 200, 2, true}, {"repeated timeout", 2, 200, 2, false}, {"successful", 0, 200, 1, true}, {"refused", 0, 403, 1, false}, {"gateway timeout", 0, 504, 2, false}, {"guard closed", 0, 503, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: rpcTransportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Host != "ipinfo.io" || r.URL.Path != "/192.0.2.1/json" {
					t.Fatal("changed check destination")
				}
				if calls <= tc.failures {
					return nil, os.ErrDeadlineExceeded
				}
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
			})}
			_, err := probeBody(context.Background(), client, "https://ipinfo.io/192.0.2.1/json")
			if (err == nil) != tc.ok || calls != tc.calls {
				t.Fatal(calls, err)
			}
		})
	}
}

func TestRetryHonorsRelayClosure(t *testing.T) {
	gate := &relayGate{}
	gate.set(time.Now().Add(time.Minute))
	window := gate.current()
	calls := 0
	_, err := retryNetworkOnce(window, func() (int, error) { calls++; gate.set(time.Time{}); return 0, io.EOF })
	if err == nil || calls != 1 {
		t.Fatal("retried a revoked lease")
	}
	spec := proxySpec{gate: gate}
	w := httptest.NewRecorder()
	spec.ServeHTTP(w, httptest.NewRequest("CONNECT", "api.openai.com:443", nil))
	if w.Code != 503 {
		t.Fatal("revoked route opened", w.Code)
	}
}

func TestSOCKSInterruptedHandshake(t *testing.T) {
	client, peer := net.Pipe()
	go func() { defer peer.Close(); var hello [3]byte; io.ReadFull(peer, hello[:]) }()
	defer client.Close()
	if err := (proxySpec{}).socks(client, "api.openai.com"); !errors.Is(err, io.EOF) {
		t.Fatal("lost transport error", err)
	}
}
