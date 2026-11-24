package main

import (
	"bytes"
	"encoding/json"
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
