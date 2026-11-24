package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAntigravityUpgradeOnlyRepairsGuardPath(t *testing.T) {
	bin := t.TempDir()
	for _, name := range []string{"agy", "guarded-codex"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("fixture"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(bin, "settings.json")
	for _, tc := range []struct{ before, after string }{
		{filepath.Join(bin, "guarded-antigravity"), filepath.Join(bin, "agy")},
		{"/custom/agy", "/custom/agy"}, {"", ""},
	} {
		data, _ := json.Marshal(map[string]any{"providerInstances": map[string]any{
			"antigravity": map[string]any{"config": map[string]string{"binaryPath": tc.before}},
			"codex":       map[string]any{"config": map[string]string{"binaryPath": "/custom/codex"}},
		}})
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := configureT3(path, bin, true); err != nil {
				t.Fatal(err)
			}
		}
		current, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			ProviderInstances map[string]struct{ Config map[string]string }
		}
		if err := json.Unmarshal(current, &result); err != nil {
			t.Fatal(err)
		}
		if result.ProviderInstances["antigravity"].Config["binaryPath"] != tc.after ||
			result.ProviderInstances["codex"].Config["binaryPath"] != "/custom/codex" {
			t.Fatal("migration selected incorrect provider paths")
		}
	}
}
