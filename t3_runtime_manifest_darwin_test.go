package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActiveRuntimeTracksPackageUpdates(t *testing.T) {
	base := t.TempDir()
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	record := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		write(path, data)
	}
	for i, name := range []string{"antigravity", "new-acp-cli"} {
		id := strings.Repeat([]string{"a", "b"}[i], 64)
		dir := filepath.Join(base, "versions", id)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, name)
		write(target, []byte("fixture"))
		record(filepath.Join(base, "active.json"), map[string]string{"releaseId": id})
		rec := filepath.Join(dir, ".install-complete.json")
		makeRecord := func(exe string, bytes int) {
			record(rec, map[string]any{"releaseId": id, "version": "2.0", "executable": map[string]any{"name": exe, "bytes": bytes}})
		}
		for _, invalid := range []string{"../other", "bad\nname"} {
			makeRecord(invalid, 7)
			if _, _, err := activeAntigravity(base); err == nil {
				t.Fatal("accepted invalid path")
			}
		}
		makeRecord(name, 99)
		if _, _, err := activeAntigravity(base); err == nil {
			t.Fatal("accepted incomplete update")
		}
		makeRecord(name, 7)
		got, version, err := activeAntigravity(base)
		if got != target || version != "2.0" || err != nil {
			t.Fatalf("active release: %q, %q, %v", got, version, err)
		}
	}
}
