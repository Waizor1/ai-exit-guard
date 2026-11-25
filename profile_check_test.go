package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
