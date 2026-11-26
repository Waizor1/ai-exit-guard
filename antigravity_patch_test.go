package main

import "testing"

func TestAntigravityReportFromLine(t *testing.T) {
	cases := []struct {
		name  string
		input string
		state string
		ok    bool
	}{
		{"single line", `{"state":"patched","rc":0}`, "patched", true},
		{"last json wins", "noise\n{\"state\":\"unpatched\",\"rc\":1}\n", "unpatched", true},
		{"trailing noise ignored", "{\"state\":\"patched\"}\nwarning", "patched", true},
		{"no json", "boom", "", false},
		{"empty", "", "", false},
		{"missing state", `{"rc":0}`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			report, ok := antigravityReportFromLine([]byte(c.input))
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if report.State != c.state {
				t.Fatalf("state = %q, want %q", report.State, c.state)
			}
		})
	}
}

func TestAntigravityFailureHint(t *testing.T) {
	cases := []struct {
		name   string
		detail string
		want   bool
	}{
		{"app management", "cannot create a temporary replacement in /Applications/Antigravity.app/Contents: Operation not permitted: macOS blocked modification of an app bundle", true},
		{"library validation", "Electron Library Validation would reject bundled frameworks", true},
		{"locked", "Antigravity is running — close it and retry", true},
		{"plain failure", "post-write signature verification failed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := antigravityFailureHint(c.detail) != ""; got != c.want {
				t.Fatalf("hint = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAntigravityAppOverride(t *testing.T) {
	t.Setenv("AI_GUARD_ANTIGRAVITY_APP", "/tmp/Antigravity.app")
	candidates := antigravityAppCandidates()
	if len(candidates) == 0 || candidates[0] != "/tmp/Antigravity.app" {
		t.Fatalf("override not first: %v", candidates)
	}
}
