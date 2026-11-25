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

func TestProfileOnlyMatchesServiceDomains(t *testing.T) {
	for _, platform := range []string{"windows", "darwin"} {
		var profile bytes.Buffer
		if err := writeSystemProfile(&profile, platform); err != nil {
			t.Fatal(err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(profile.Bytes(), &document); err != nil {
			t.Fatal(err)
		}
		key, hostKey := "proxyRules", "targetHosts"
		if platform == "windows" {
			key, hostKey = "ProxyRules", "TargetDomains"
		}
		var rules []map[string]any
		if err := json.Unmarshal(document[key], &rules); err != nil || len(rules) == 0 {
			t.Fatal("missing rules", err)
		}
		for _, rule := range rules {
			host := strings.TrimPrefix(rule[hostKey].(string), "*.")
			if !aiHost(host) {
				t.Fatalf("%s captures a non-service destination: %v", platform, rule)
			}
		}
		processKey := "processNames"
		suffix := ""
		if platform == "windows" {
			processKey = "ProcessName"
			suffix = ".exe"
		}
		captured := func(app, host string) bool {
			for _, rule := range rules {
				process := rule[processKey].(string)
				if process != "*" && !strings.EqualFold(process, app+suffix) {
					continue
				}
				pattern := rule[hostKey].(string)
				if pattern == host || (strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:])) {
					return true
				}
			}
			return false
		}
		for _, app := range []string{"T3 Code (Beta)", "codex", "claude", "antigravity", "unknown-tool"} {
			for _, host := range []string{"api.openai.com", "claude.ai", "daily-cloudcode-pa.googleapis.com", geminiAPI} {
				if !captured(app, host) {
					t.Errorf("%s %s missed %s", platform, app, host)
				}
			}
			for _, host := range []string{"localhost", "127.0.0.1", "github.com", "homelab.local", "registry.npmjs.org", "models.opencode.ai", "api.openai.com.example.org"} {
				if captured(app, host) {
					t.Errorf("%s %s captured %s", platform, app, host)
				}
			}
			for _, host := range []string{"oauth2.googleapis.com", "www.googleapis.com"} {
				want := app == "T3 Code (Beta)" || app == "antigravity"
				if captured(app, host) != want {
					t.Errorf("%s %s Google account route for %s", platform, app, host)
				}
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

func TestTransientDiagnosticCannotMaskChangedExit(t *testing.T) {
	var countries map[string]string
	if err := json.Unmarshal(regionData, &countries); err != nil {
		t.Fatal(err)
	}
	cfg := desktopConfig{Expected: "192.0.2.10"}
	now := time.Unix(1795305600, 0)
	for _, r := range []result{{}, {Status: "unknown", IP: cfg.Expected}, {TraceCountry: "DE", IP: cfg.Expected}} {
		if !cfg.temporaryReading(r, "ChatGPT", countries, now) {
			t.Fatalf("unexpected revocation %#v", r)
		}
	}
	risk := 78.0
	for _, r := range []result{{Status: "red"}, {IP: "192.0.2.11"}, {TraceCountry: "RU"}, {Risk: &risk}, {AssessmentIP: "192.0.2.12"}, {Status: "amber"}} {
		if cfg.temporaryReading(r, "ChatGPT", countries, now) {
			t.Fatalf("explicit risk retained %#v", r)
		}
	}
}

func TestDesktopAdvisoryDistinguishesConfirmedRisk(t *testing.T) {
	cfg := desktopConfig{Expected: "93.184.216.34", ProxyOnly: true}
	countries := map[string]string{"Claude": "DE FR"}
	normal := result{Host: "api.anthropic.com", IP: cfg.Expected, AssessmentIP: cfg.Expected, Country: "DE", TraceCountry: "DE", InfoChecked: true}
	if cfg.highRisk(normal, countries) || cfg.highRisk(result{Host: normal.Host}, countries) {
		t.Fatal("missing evidence reported as dangerous")
	}
	for _, modify := range []func(*result){
		func(r *result) { r.IP = "93.184.216.35" },
		func(r *result) { r.Status = "red" },
		func(r *result) { r.TraceCountry = "RU" },
		func(r *result) { v := 67.0; r.Risk = &v },
	} {
		r := normal
		modify(&r)
		if !cfg.highRisk(r, countries) {
			t.Fatalf("positive evidence not shown as high risk: %+v", r)
		}
	}
}
