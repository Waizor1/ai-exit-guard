package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChecks(t *testing.T) {
	for _, v := range []struct {
		ip    string
		score float64
		want  string
	}{{"1.1.1.1", 0, "red"}, {"1.1.1.1", 100.0 / 3, "red"}, {"1.1.1.1", 34, "amber"}, {"1.1.1.1", 200.0 / 3, "amber"}, {"1.1.1.1", 67, "green"}, {"8.8.8.8", 99, "split"}, {"1.1.1.1", 101, "unknown"}} {
		tr := trustResult{ip: v.ip, scores: map[string]struct {
			Score *float64 `json:"trust_score"`
		}{"claude": {&v.score}}}
		r := result{IP: "1.1.1.1"}
		classify(&r, "claude", tr)
		if r.Status != v.want || r.Status == "split" && r.Trust != nil {
			t.Fatal(v, r)
		}
	}
}
func TestTrace(t *testing.T) {
	for _, v := range []struct {
		body string
		ok   bool
	}{{"h=claude.ai\nip=1.1.1.1", true}, {"h=claude.ai\nip=2606:4700:4700::1111", true}, {"h=wrong\nip=1.1.1.1", false}, {"h=claude.ai\nip=127.0.0.1", false}, {"h=claude.ai\nip=1.1.1.1\nip=8.8.8.8", false}} {
		_, _, e := traceExit([]byte(v.body), "claude.ai")
		if (e == nil) != v.ok {
			t.Fatal(v)
		}
	}
}
func TestLookup(t *testing.T) {
	for _, v := range []struct {
		payload string
		ok      bool
	}{{`{"code":0,"data":{"ip":"1.1.1.1","fraud_score":0}}`, true}, {`{"code":0,"data":{"ip":"8.8.8.8","fraud_score":0}}`, false}, {`{"code":0,"data":{"ip":"1.1.1.1"}}`, false}, {`{"code":2}`, false}} {
		_, e := decodeRisk([]byte(v.payload), "1.1.1.1")
		if (e == nil) != v.ok {
			t.Fatal(v)
		}
	}
}
func TestTrustEvidence(t *testing.T) {
	for _, closeConn := range []bool{false, true} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if closeConn {
				w.Header().Set("Connection", "close")
			}
			if r.URL.Path == "/ip.json" {
				fmt.Fprint(w, `{"ip":"1.1.1.1"}`)
			} else {
				fmt.Fprint(w, `{"code":0,"data":{"claude":{"trust_score":17},"chatgpt":{"trust_score":88}}}`)
			}
		}))
		c := s.Client()
		v := trustAt(context.Background(), c, s.URL)
		s.Close()
		if (v.err != nil) != closeConn {
			t.Fatal(v.err)
		}
		if !closeConn {
			for key, want := range map[string]string{"claude": "red", "chatgpt": "green"} {
				r := result{IP: v.ip}
				classify(&r, key, v)
				if r.Status != want {
					t.Fatal(key, r)
				}
			}
		}
	}
}
func TestIPinfo(t *testing.T) {
	b := []byte(`{"ip":"1.1.1.1","country":"AU","org":"AS13335 Cloudflare, Inc."}`)
	x, e := decodeInfo(b, "1.1.1.1")
	if e != nil || x.Country != "AU" || x.Org == "" {
		t.Fatal(x, e)
	}
	if _, e = decodeInfo(b, "8.8.8.8"); e == nil {
		t.Fatal("mismatched IPinfo attribution")
	}
}
func TestOptionalPrivacy(t *testing.T) {
	b := []byte(`{"ip":"1.1.1.1","country":"AU","anycast":true,"privacy":{"vpn":false,"hosting":true}}`)
	x, err := decodeInfo(b, "1.1.1.1")
	if err != nil || fmt.Sprint(x.signals()) != "[Anycast Hosting]" {
		t.Fatal(x, err)
	}
	x, err = decodeInfo([]byte(`{"ip":"1.1.1.1","org":"AS13335"}`), "1.1.1.1")
	if err != nil || len(x.signals()) != 0 {
		t.Fatal("missing privacy fields", x, err)
	}
}

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIPinfoQueriesOnlyObservedServiceExits(t *testing.T) {
	exits := map[string]string{"claude.ai": "1.1.1.1", "api.anthropic.com": "1.1.1.1", "chatgpt.com": "8.8.8.8"}
	requests := map[string]int{}
	var mu sync.Mutex
	transport := fixtureTransport(func(r *http.Request) (*http.Response, error) {
		var body string
		code := 200
		switch r.URL.Host {
		case "ipinfo.io":
			mu.Lock()
			requests[r.URL.Path]++
			mu.Unlock()
			ip := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/json")
			body = fmt.Sprintf(`{"ip":%q,"org":%q}`, ip, "network "+ip)
		case "ip123.in":
			body = fmt.Sprintf(`{"code":0,"data":{"ip":%q,"fraud_score":4}}`, r.URL.Query().Get("ip"))
		default:
			if ip := exits[r.URL.Host]; ip != "" {
				body = "h=" + r.URL.Host + "\nip=" + ip + "\nloc=DE"
			} else {
				code = 503
			}
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	c := checker{ctx: context.Background(), client: &http.Client{Transport: transport}}
	c.trace = func(ctx context.Context, address string) ([]byte, error) {
		b, _, err := get(ctx, c.client, address)
		return b, err
	}
	c.once.Do(func() { c.trust.ip = "9.9.9.9" })
	final := map[string]result{}
	for r := range c.results() {
		final[r.Host] = r
	}
	if !reflect.DeepEqual(requests, map[string]int{"/1.1.1.1/json": 1, "/8.8.8.8/json": 1}) {
		t.Fatal(requests)
	}
	for host, ip := range exits {
		r := final[host]
		if r.TraceCountry != "DE" || r.IP != ip || r.Network != "network "+ip || r.Status != "split" || r.Trust != nil {
			t.Fatal(host, r)
		}
	}
	missing := final["api.openai.com"]
	if missing.Status != "unknown" || missing.Network != "" || missing.IP != "" {
		t.Fatal(missing)
	}
}

func TestCancelStopsSystemProbe(t *testing.T) {
	connected := make(chan struct{}, 1)
	disconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connected <- struct{}{}
		<-r.Context().Done()
		disconnected <- struct{}{}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := systemTrace(ctx, server.URL); done <- err }()
	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not connect")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled command succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("curl survived cancellation")
	}
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("connection survived cancellation")
	}
}
