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

func filterCommand(ctx context.Context, mode string) error {
	if mode == "filter-run" {
		var profile bytes.Buffer
		if err := writeSystemProfile(&profile, "darwin"); err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, bridgeTool, "--profile", "-", "--verbose", "0")
		cmd.Stdin = &profile
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
		cmd.WaitDelay = 5 * time.Second
		return cmd.Run()
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
