package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSystemProfiles(t *testing.T) {
	for _, platform := range []string{"darwin", "windows"} {
		var b bytes.Buffer
		if err := writeSystemProfile(&b, platform); err != nil {
			t.Fatal(err)
		}
		var p map[string]json.RawMessage
		if err := json.Unmarshal(b.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		var rules []map[string]any
		k := "proxyRules"
		process, hosts, action, protocol := "processNames", "targetHosts", "action", "protocol"
		if platform == "windows" {
			k = "ProxyRules"
			process, hosts, action, protocol = "ProcessName", "TargetDomains", "Action", "Protocol"
		}
		if err := json.Unmarshal(p[k], &rules); err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, r := range rules {
			if r[process] == "*" {
				h := r[hosts].(string)
				if !aiHost(strings.TrimPrefix(h, "*.")) || h == "*" || h == googleHost {
					t.Fatalf("overbroad %s %s", platform, h)
				}
				if platform == "darwin" && r[protocol] == "UDP" {
					t.Fatal("macOS cannot scope UDP by hostname")
				}
				if r[action] == "PROXY" || r[action] == "guard" {
					found[h] = true
				}
			}
		}
		for _, d := range aiDomains {
			if !found[d] || !found["*."+d] {
				t.Fatal("missing route", platform, d)
			}
		}
	}
}

func TestT3LoopbackRule(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	folder := filepath.Join(home, ".t3", "userdata")
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://127.0.0.1:3773", "http://127.0.0.1:39178", "http://127.0.0.1:65536", "https://outside.example:3773", "http://127.0.0.1:3773/path"} {
		raw, _ := json.Marshal(map[string]string{"origin": origin})
		if err := os.WriteFile(filepath.Join(folder, "server-runtime.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := writeSystemProfile(&b, "darwin"); err != nil {
			t.Fatal(err)
		}
		var profile struct {
			ProxyRules []struct{ Name, TargetHosts, TargetPorts, Action, Protocol, ProcessNames string }
		}
		if err := json.Unmarshal(b.Bytes(), &profile); err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, r := range profile.ProxyRules {
			if r.Name != "Local T3 MCP" {
				continue
			}
			if r.TargetHosts != "127.0.0.1" || r.TargetPorts != "3773" || r.Action != "DIRECT" || r.Protocol != "TCP" || r.ProcessNames == "*" {
				t.Fatal(r)
			}
			count++
		}
		if (origin == "http://127.0.0.1:3773" && count != 5) || (origin != "http://127.0.0.1:3773" && count != 0) {
			t.Fatal(origin, count)
		}
	}
}

func TestDesktopVerdict(t *testing.T) {
	var countries map[string]string
	if err := json.Unmarshal(regionData, &countries); err != nil {
		t.Fatal(err)
	}
	risk, trust := 10., 92.
	r := result{IP: "192.0.2.3", AssessmentIP: "192.0.2.3", Host: "api.openai.com", Country: "DE", TraceCountry: "DE", InfoChecked: true, Status: "green", Risk: &risk, Trust: &trust}
	now := time.Unix(1795305600, 0)
	if (desktopConfig{Expected: r.IP}).refusal(r, countries, now) != "" {
		t.Fatal("refused a checked route")
	}
	offline := r
	offline.InfoChecked, offline.InfoUnavailable, offline.Country = false, true, ""
	cfg := desktopConfig{Expected: r.IP}
	if reason := cfg.refusal(offline, countries, now); reason != "" {
		t.Fatal("supplemental outage", reason)
	}
	offline.TraceCountry = "RU"
	if cfg.refusal(offline, countries, now) == "" {
		t.Fatal("unverified region accepted")
	}
	for _, c := range []struct {
		r   result
		pin string
		at  time.Time
	}{{r, "192.0.2.4", now}, {r, r.IP, now.AddDate(0, 0, 91)}} {
		if (desktopConfig{Expected: c.pin}).refusal(c.r, countries, c.at) == "" {
			t.Fatal("unexpected open")
		}
	}
	for _, mutate := range []func(*result){func(r *result) { r.Risk = nil }, func(r *result) { r.AssessmentIP = "" }, func(r *result) { r.TraceCountry = "RU" }, func(r *result) { r.InfoChecked = false }, func(r *result) { r.Status = "red" }} {
		v := r
		mutate(&v)
		if (desktopConfig{Expected: r.IP}).refusal(v, countries, now) == "" {
			t.Fatal("permitted incomplete or red verdict")
		}
	}
}

func TestAntigravityCountryException(t *testing.T) {
	var countries map[string]string
	if err := json.Unmarshal(regionData, &countries); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1795305600, 0)
	risk, trust := 0., 99.
	r := result{Host: googleHost, IP: "192.0.2.3", AssessmentIP: "192.0.2.3", Status: "google", TraceCountry: "NL", Country: "DE", InfoChecked: true, Risk: &risk, Trust: &trust}
	cfg := desktopConfig{Expected: r.IP}
	if why := cfg.refusal(r, countries, now); !strings.Contains(why, "Google: NL, IPinfo: DE") {
		t.Fatal(why)
	}
	cfg.AllowGoogleCountryMismatch = true
	if why := cfg.refusal(r, countries, now); why != "" {
		t.Fatal(why)
	}
	high := 34.
	for name, mutate := range map[string]func(*result){
		"Google region":      func(v *result) { v.TraceCountry = "RU" },
		"IPinfo region":      func(v *result) { v.Country = "RU" },
		"changed exit":       func(v *result) { v.IP = "192.0.2.9" },
		"wrong assessment":   func(v *result) { v.AssessmentIP = "192.0.2.1" },
		"risk":               func(v *result) { v.Risk = &high },
		"missing risk":       func(v *result) { v.Risk = nil },
		"unconfirmed region": func(v *result) { v.InfoChecked = false },
		"failed probe":       func(v *result) { v.Status = "unknown" },
		"Claude isolated":    func(v *result) { v.Host = "claude.ai"; v.Status = "green" },
		"ChatGPT isolated":   func(v *result) { v.Host = "chatgpt.com"; v.Status = "green" },
	} {
		t.Run(name, func(t *testing.T) {
			v := r
			mutate(&v)
			if cfg.refusal(v, countries, now) == "" {
				t.Fatal("route opened")
			}
		})
	}
	cfg.Profiles = map[string]individualProxy{"Antigravity": {Expected: "192.0.2.99"}}
	if cfg.refusal(r, countries, now) == "" {
		t.Fatal("common pin used for individual route")
	}
}
