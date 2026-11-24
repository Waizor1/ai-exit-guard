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
	"strings"
	"time"
)

const filterService = "local.aiexitguard.filter"
const bridgeTool = "/Applications/ProxyBridge.app/Contents/MacOS/ProxyBridge"

func filterCommand(ctx context.Context, mode string) error {
	if mode == "filter-run" {
		// Reconfigure only our own ProxyBridge CLI. Changes to other preferences
		// never interrupt it unless the actual routing mode has changed.
		readMode := func() bool {
			b, e := exec.CommandContext(ctx, "/usr/bin/defaults", "read", "local.aiexitguard.menu", "proxyOnly").Output()
			return e == nil && strings.TrimSpace(string(b)) == "1"
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		preferenceFile := filepath.Join(home, "Library", "Preferences", "local.aiexitguard.menu.plist")
		preferenceStamp := func() time.Time {
			if st, e := os.Stat(preferenceFile); e == nil {
				return st.ModTime()
			}
			return time.Time{}
		}
		for ctx.Err() == nil {
			stamp := preferenceStamp()
			mode := readMode()
			var profile bytes.Buffer
			if err := writeRoutingProfile(&profile, "darwin", mode); err != nil {
				return err
			}
			child, stop := context.WithCancel(ctx)
			cmd := exec.CommandContext(child, bridgeTool, "--profile", "-", "--verbose", "0")
			cmd.Stdin = &profile
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
			cmd.WaitDelay = 5 * time.Second
			if err := cmd.Start(); err != nil {
				stop()
				return err
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			timer := time.NewTicker(5 * time.Second)
		watch:
			for {
				select {
				case err := <-done:
					timer.Stop()
					stop()
					return err
				case <-timer.C:
					nextStamp := preferenceStamp()
					if nextStamp.Equal(stamp) {
						continue
					}
					stamp = nextStamp
					if readMode() != mode {
						break watch
					}
				case <-ctx.Done():
					break watch
				}
			}
			timer.Stop()
			stop()
			<-done
		}
		return ctx.Err()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	file := filepath.Join(home, "Library", "LaunchAgents", filterService+".plist")
	ctl := func(args ...string) error { return exec.CommandContext(ctx, "/bin/launchctl", args...).Run() }
	loaded := ctl("print", domain+"/"+filterService) == nil
	if mode == "filter-off" {
		if loaded {
			if err = ctl("bootout", domain+"/"+filterService); err != nil {
				return err
			}
		}
		if err = os.Remove(file); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if _, err = os.Stat(bridgeTool); err != nil {
		return fmt.Errorf("установите ProxyBridge для Mac")
	}
	if err = os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	const agent = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>local.aiexitguard.filter</string>
<key>ProgramArguments</key><array><string>/Applications/AI Exit Guard.app/Contents/Resources/guard</string><string>filter-run</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>60</integer>
</dict></plist>`
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
