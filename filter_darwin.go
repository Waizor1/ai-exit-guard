//go:build darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

const filterService = "local.aiexitguard.filter"
const bridgeTool = "/Applications/ProxyBridge.app/Contents/MacOS/ProxyBridge"

const agent = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>local.aiexitguard.filter</string>
<key>ProgramArguments</key><array><string>/Applications/AI Exit Guard.app/Contents/Resources/guard</string><string>filter-run</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>60</integer>
</dict></plist>`

func filterCommand(ctx context.Context, mode string) error {
	if mode == "filter-run" {
		var profile bytes.Buffer
		if err := writeSystemProfile(&profile, "darwin"); err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, bridgeTool, "--profile", "-", "--verbose", "0")
		cmd.Stdin = &profile
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
		cmd.WaitDelay = 5 * time.Second
		return cmd.Run()
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	file := filepath.Join(home, "Library", "LaunchAgents", filterService+".plist")
	ctl := func(args ...string) error { return exec.CommandContext(ctx, "/bin/launchctl", args...).Run() }
	paused := filepath.Join(home, "Library", "Application Support", "AI Exit Guard", "paused-filter.plist")
	if mode == "filter-pause" || mode == "filter-resume" || mode == "filter-refresh" {
		return filterLifecycle(mode, file, paused, domain, ctl)
	}
	if mode == "filter-off" {
		if err := filterLifecycle("filter-pause", file, paused, domain, ctl); err != nil {
			return err
		}
		previous, err := os.ReadFile(paused)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil || string(previous) != agent {
			return fmt.Errorf("профиль системного фильтра изменён вручную")
		}
		return os.Remove(paused)
	}
	if _, err := os.Lstat(paused); err == nil {
		return filterLifecycle("filter-resume", file, paused, domain, ctl)
	} else if !os.IsNotExist(err) {
		return err
	}
	loaded := ctl("print", domain+"/"+filterService) == nil
	if _, err = os.Stat(bridgeTool); err != nil {
		return fmt.Errorf("установите ProxyBridge для Mac")
	}
	if err = os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}

	if old, err := os.ReadFile(file); err == nil && string(old) != agent {
		return fmt.Errorf("файл автозапуска изменён вручную")
	}
	if err = os.WriteFile(file, []byte(agent), 0600); err != nil {
		return err
	}
	if !loaded {
		return ctl("bootstrap", domain, file)
	}
	return nil
}

// Pause the existing Guard-owned launch agent while the relay is intentionally
// offline. A process crash is handled separately and keeps the route closed.
func filterLifecycle(mode, file, paused, domain string, ctl func(...string) error) error {
	source, target := file, paused
	if mode != "filter-pause" {
		source, target = paused, file
	}
	check := func(path string) (bool, error) {
		st, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !st.Mode().IsRegular() {
			return false, fmt.Errorf("изменённый файл системного фильтра")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		if string(b) != agent {
			return false, fmt.Errorf("профиль системного фильтра изменён вручную")
		}
		return true, nil
	}
	exists, err := check(source)
	if err != nil {
		return err
	}
	job := domain + "/" + filterService
	if !exists {
		if mode == "filter-refresh" {
			present, err := check(file)
			if err != nil {
				return err
			}
			if present && ctl("print", job) == nil {
				return ctl("kickstart", "-k", job)
			}
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	// Link refuses to overwrite a concurrent installation or a foreign file.
	if err := os.Link(source, target); err != nil {
		// Complete an interrupted link/remove pair only for the same inode.
		left, e1 := os.Lstat(source)
		right, e2 := os.Lstat(target)
		if !os.IsExist(err) || e1 != nil || e2 != nil || !os.SameFile(left, right) {
			return err
		}
	}
	if err := os.Remove(source); err != nil {
		_ = os.Remove(target)
		return err
	}
	if mode == "filter-pause" {
		if ctl("print", job) == nil {
			err = ctl("bootout", job)
		}
	} else if ctl("print", job) != nil {
		err = ctl("bootstrap", domain, file)
	}
	if err != nil {
		if os.Link(target, source) == nil {
			_ = os.Remove(target)
		}
	}
	return err
}
