package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type probeTransport func(*http.Request) (*http.Response, error)

func (f probeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
			client := &http.Client{Transport: probeTransport(func(r *http.Request) (*http.Response, error) {
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

func TestIP123RetryEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                string
		status              int
		failIP, failTrust   int
		retryAfter          string
		closeConn           bool
		ipCalls, trustCalls int
		want                string
	}{
		{"both recover", 502, 1, 1, "", false, 2, 2, "green"},
		{"recover trust", 503, 0, 1, "", false, 1, 2, "green"},
		{"persistent IP failure", 502, 2, 0, "", false, 2, 0, "unknown"},
		{"persistent trust failure", 503, 0, 2, "", false, 1, 2, "unknown"},
		{"rate limited", 429, 0, 1, "", false, 1, 1, "unknown"},
		{"retry after", 503, 0, 1, "60", false, 1, 1, "unknown"},
		{"new connection on retry", 502, 0, 1, "", true, 1, 2, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var ipCalls, trustCalls int
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("unexpected method %s", r.Method)
				}
				switch r.URL.Path {
				case "/ip.json":
					ipCalls++
					if ipCalls > tc.failIP {
						fmt.Fprint(w, `{"ip":"1.1.1.1"}`)
						return
					}
				case "/ai_trust":
					trustCalls++
					if trustCalls > tc.failTrust {
						fmt.Fprint(w, `{"code":0,"data":{"claude":{"trust_score":90}}}`)
						return
					}
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					return
				}
				if tc.closeConn {
					w.Header().Set("Connection", "close")
				}
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				http.Error(w, "gateway error", tc.status)
			}))
			v := trustAt(context.Background(), s.Client(), s.URL)
			s.Close()
			r := result{IP: "1.1.1.1"}
			classify(&r, "claude", v)
			if ipCalls != tc.ipCalls || trustCalls != tc.trustCalls || r.Status != tc.want || (r.Trust != nil) != (tc.want == "green") {
				t.Fatalf("ip=%d trust=%d status=%s score=%v err=%v", ipCalls, trustCalls, r.Status, r.Trust, v.err)
			}
		})
	}
}

func TestIP123TemporaryTransport(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cause     error
		wantCalls int
	}{
		{"temporary DNS", &net.DNSError{IsTemporary: true}, 2},
		{"permanent DNS", &net.DNSError{IsNotFound: true}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: probeTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.URL.Host != "ip123.in" || r.URL.Path != "/api/v2/search_ip_page" || r.URL.Query().Get("ip") != "1.1.1.1" {
					t.Fatalf("changed destination %s", r.URL)
				}
				return nil, tc.cause
			})}
			_, err := probeBody(context.Background(), client, api+"/search_ip_page?ip=1.1.1.1")
			if calls != tc.wantCalls || !errors.Is(err, tc.cause) {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}
