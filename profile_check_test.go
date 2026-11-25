package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestSavedProfileMeasurement(t *testing.T) {
	good := profileMeasurement{"192.0.2.19", "DE"}
	for _, tc := range []struct {
		want     string
		expected string
		rows     []profileMeasurement
	}{
		{"ok", good.IP, []profileMeasurement{good, good}},
		{"changed", "192.0.2.20", []profileMeasurement{good}},
		{"inconsistent", "", []profileMeasurement{good, {"192.0.2.20", "DE"}}},
		{"inconsistent", "", []profileMeasurement{good, {good.IP, "NL"}}},
		{"unavailable", good.IP, []profileMeasurement{good, {}}},
		{"unavailable", good.IP, []profileMeasurement{{good.IP, "XX"}}},
	} {
		got := summarizeProfile(tc.rows, tc.expected)
		if got.Status != tc.want || (tc.want == "ok" || tc.want == "changed") && got.profileMeasurement != good {
			t.Fatalf("%s: %#v", tc.want, got)
		}
	}
}
func TestSavedProfileChecksOnlySelectedHostsThroughProxy(t *testing.T) {
	for _, service := range []string{"Claude", "ChatGPT", "Antigravity", ""} {
		t.Run("service-"+service, func(t *testing.T) {
			var mu sync.Mutex
			seen := map[string]bool{}
			p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" {
					t.Errorf("unexpected method %s", r.Method)
				}
				mu.Lock()
				seen[r.Host] = true
				mu.Unlock()
				w.WriteHeader(http.StatusProxyAuthRequired)
			}))
			defer p.Close()
			u, _ := url.Parse(p.URL)
			port, _ := strconv.Atoi(u.Port())
			ep := proxySpec{Scheme: "http", Host: u.Hostname(), Port: port, User: "user", Password: "secret"}
			input, _ := json.Marshal(profileRequest{Endpoint: ep, Service: service})
			var out bytes.Buffer
			if n := profileCheckCommand(context.Background(), bytes.NewReader(input), &out); n != 0 {
				t.Fatal(n)
			}
			if out.String() != "{\"IP\":\"\",\"Country\":\"\",\"Status\":\"unavailable\"}\n" {
				t.Fatal("unexpected response or credentials exposed")
			}
			want := []string{}
			for _, target := range targets {
				if service == "" || serviceForHost(target.host) == service {
					want = append(want, target.host)
				}
			}
			if service == "Antigravity" {
				want = []string{"accounts.google.com", "ip123.in"}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(want) != len(seen) {
				t.Fatal("unexpected proxy destinations", seen)
			}
			for _, h := range want {
				if !seen[h+":443"] {
					t.Fatal("missing destination", h)
				}
			}
		})
	}
}

func TestGoogleProfileIdentity(t *testing.T) {
	const validTrace = "h=www.cloudflare.com\nip=1.1.1.1\nloc=US"
	for _, tc := range []struct {
		name, identity, trace, country, wantIP, errorText string
		wantPrimary, wantFallback                         bool
	}{
		{"IP123 preferred", `{"ip":"8.8.8.8"}`, validTrace, "DE", "8.8.8.8", "", true, false},
		{"IP123 unavailable", "", validTrace, "DE", "1.1.1.1", "", false, true},
		{"invalid primary identity", `{"ip":"10.0.0.1"}`, validTrace, "DE", "1.1.1.1", "", false, true},
		{"unexpected trace host", "", "h=example.org\nip=1.1.1.1", "DE", "", "внешний IP", false, true},
		{"private trace IP", "", "h=www.cloudflare.com\nip=127.0.0.1", "DE", "", "внешний IP", false, true},
		{"absent Google region", "", validTrace, "XX", "1.1.1.1", "Google не сообщил страну", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fallback bool
			var primaryRequests int
			client := &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
				var body string
				code := http.StatusOK
				switch {
				case r.URL.Host == googleHost && r.URL.Path == "/ServiceLogin":
					body = `<input name="region" value="` + tc.country + `">`
				case r.URL.Host == "ip123.in" && r.URL.Path == "/api/v2/ip.json":
					primaryRequests++
					body = tc.identity
					if body == "" {
						code = http.StatusServiceUnavailable
					}
				case r.URL.Host == fallbackIdentityHost && r.URL.Path == "/cdn-cgi/trace":
					body, fallback = tc.trace, true
				default:
					t.Errorf("unexpected request to %s", r.URL)
					code = http.StatusForbidden
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			row, primary, err := measureGoogle(context.Background(), client)
			if primaryRequests != 1 {
				t.Fatalf("IP123 identity requests = %d", primaryRequests)
			}
			if row.IP != tc.wantIP || primary != tc.wantPrimary || fallback != tc.wantFallback {
				t.Fatalf("row=%+v primary=%v fallback=%v", row, primary, fallback)
			}
			if tc.country != "XX" && row.Country != tc.country {
				t.Fatalf("lost verified Google country %q", tc.country)
			}
			if tc.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errorText) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || row.Country != tc.country {
				t.Fatalf("Google country = %q, err=%v", row.Country, err)
			}
			if tc.wantFallback && summarizeProfile([]profileMeasurement{row}, "8.8.8.8").Status != "changed" {
				t.Fatal("fallback identity bypassed the saved IP pin")
			}
		})
	}
}
func TestGoogleFallbackUsesConfiguredTunnel(t *testing.T) {
	seen := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			t.Errorf("method = %s", r.Method)
		}
		seen <- r.Host
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	c := (proxySpec{Scheme: "http", Host: u.Hostname(), Port: port}).probeClient()
	defer c.CloseIdleConnections()
	if _, _, err := measureGoogle(context.Background(), c); err == nil {
		t.Fatal("refused upstream accepted")
	}
	close(seen)
	hosts := map[string]int{}
	for host := range seen {
		hosts[host]++
	}
	for _, h := range []string{googleHost, "ip123.in", fallbackIdentityHost} {
		if hosts[h+":443"] != 1 {
			t.Fatalf("unexpected CONNECT destinations %v", hosts)
		}
	}
	if aiHost(fallbackIdentityHost) {
		t.Fatal("diagnostic fallback became a relay destination")
	}
}

func TestSavedSingleProfilePreservesPartialEvidence(t *testing.T) {
	for _, tc := range []struct {
		row    profileMeasurement
		status string
	}{
		{profileMeasurement{Country: "RU"}, "unavailable"},
		{profileMeasurement{IP: "8.8.8.8"}, "changed"},
		{profileMeasurement{IP: "1.1.1.1"}, "unavailable"},
	} {
		r := summarizeProfile([]profileMeasurement{tc.row}, "1.1.1.1")
		if r.profileMeasurement != tc.row || r.Status != tc.status {
			t.Fatal(r)
		}
	}
}
