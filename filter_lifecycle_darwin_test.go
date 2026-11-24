package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFilterFollowsRelay(t *testing.T) {
	root := t.TempDir()
	file, paused := filepath.Join(root, "active.plist"), filepath.Join(root, "owned", "paused.plist")
	if err := os.WriteFile(file, []byte(agent), 0600); err != nil {
		t.Fatal(err)
	}
	loaded := true
	restarts := 0
	fail := ""
	ctl := func(a ...string) error {
		if a[0] == fail {
			return errors.New("fixture failure")
		}
		switch a[0] {
		case "print":
			if !loaded {
				return os.ErrNotExist
			}
		case "bootstrap":
			loaded = true
		case "bootout":
			loaded = false
		case "kickstart":
			restarts++
		default:
			t.Fatal(a)
		}
		return nil
	}
	run := func(mode string) {
		t.Helper()
		if err := filterLifecycle(mode, file, paused, "gui/fixture", ctl); err != nil {
			t.Fatal(err)
		}
	}
	run("filter-refresh")
	if restarts != 1 {
		t.Fatal("old active filter still running")
	}
	fail = "bootout"
	if filterLifecycle("filter-pause", file, paused, "gui/fixture", ctl) == nil {
		t.Fatal("failed pause reported success")
	}
	if _, err := os.Stat(file); err != nil || !loaded {
		t.Fatal("lost existing filter", err)
	}
	fail = ""
	run("filter-pause")
	run("filter-pause")
	if loaded {
		t.Fatal("filter still captures traffic on intentional stop")
	}
	fail = "bootstrap"
	if filterLifecycle("filter-resume", file, paused, "gui/fixture", ctl) == nil {
		t.Fatal("failed resume reported success")
	}
	if _, err := os.Stat(paused); err != nil {
		t.Fatal("lost previous configuration", err)
	}
	fail = ""
	run("filter-resume")
	run("filter-resume")
	if !loaded || restarts != 1 {
		t.Fatal("failed to restore original filter once")
	}
	if err := os.WriteFile(file, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if filterLifecycle("filter-pause", file, paused, "gui/fixture", ctl) == nil || !loaded {
		t.Fatal("modified user configuration")
	}
}
