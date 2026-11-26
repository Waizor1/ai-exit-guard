package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// antigravityReport is the single JSON line the menu app decodes.
type antigravityReport struct {
	State    string `json:"state"`
	Path     string `json:"path,omitempty"`
	Version  string `json:"version,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Rc       int    `json:"rc"`
	Engine   string `json:"engine,omitempty"`
	EngineAt string `json:"engineAt,omitempty"`
	Update   string `json:"update,omitempty"`
	Commit   string `json:"commit,omitempty"`
}

// antigravityAppCandidates lists the bundles Guard can patch, most likely first.
func antigravityAppCandidates() []string {
	var out []string
	if custom := os.Getenv("AI_GUARD_ANTIGRAVITY_APP"); custom != "" {
		out = append(out, custom)
	}
	out = append(out, "/Applications/Antigravity.app")
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, "Applications", "Antigravity.app"))
	}
	return out
}

func antigravityApp() (string, error) {
	for _, app := range antigravityAppCandidates() {
		info, err := os.Stat(app)
		if err == nil && info.IsDir() {
			return app, nil
		}
	}
	return "", os.ErrNotExist
}

func antigravityVersion(app string) string {
	plist := filepath.Join(app, "Contents", "Info.plist")
	out, err := exec.Command("/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", plist).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func antigravityBinary(app string) string {
	return filepath.Join(app, "Contents", "Resources", "bin", "language_server")
}

func antigravityPython() string {
	for _, path := range []string{"/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	if path, err := exec.LookPath("python3"); err == nil {
		return path
	}
	return ""
}

// antigravityPatcherAssets points at the bundled bridge and pinned patcher.
func antigravityPatcherAssets() (bridge string, patcher string, err error) {
	dir, err := antigravityAssetsDir()
	if err != nil {
		return "", "", err
	}
	bridge = filepath.Join(dir, "bridge.py")
	patcher = filepath.Join(dir, "antigravity_patcher.py")
	for _, path := range []string{bridge, patcher} {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return "", "", fmt.Errorf("antigravity patcher asset missing: %s", path)
		}
	}
	return bridge, patcher, nil
}

type antigravityEngine struct {
	script      string
	kind        string
	installedAt string
}

// antigravityEngines prefers the downloaded copy and always keeps the bundled
// one as a fallback.
func antigravityEngines(bundled string) []antigravityEngine {
	out := []antigravityEngine{{script: bundled, kind: "bundled"}}
	if script, state, ok := antigravityDownloadedEngine(); ok && script != bundled {
		out = append([]antigravityEngine{{script: script, kind: "downloaded", installedAt: state.InstalledAt}}, out...)
	}
	return out
}

// antigravityFailureHint turns the patcher's macOS error into one actionable line.
func antigravityFailureHint(detail string) string {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "operation not permitted") && strings.Contains(lower, "app bundle"):
		return "macOS не даёт изменять приложение: включите App Management для AI Exit Guard в Системных настройках → Конфиденциальность и безопасность."
	case strings.Contains(lower, "library validation"):
		return "macOS отклонил переподпись. Закройте Antigravity и повторите."
	case strings.Contains(lower, "running") || strings.Contains(lower, "locked"):
		return "Закройте Antigravity и повторите."
	}
	return ""
}

// antigravityReportFromLine decodes the last JSON line of the bridge output.
func antigravityReportFromLine(data []byte) (antigravityReport, bool) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var report antigravityReport
		if err := json.Unmarshal([]byte(line), &report); err == nil && report.State != "" {
			return report, true
		}
	}
	return antigravityReport{}, false
}

func antigravityInvoke(ctx context.Context, python, bridge, script, action, binary string) antigravityReport {
	timeout := 90 * time.Second
	if action != "status" && action != "selftest" {
		timeout = 20 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := commandWithEnv(runCtx, python, bridge, action, binary, script)
	out, err := cmd.CombinedOutput()
	report, ok := antigravityReportFromLine(out)
	if ok {
		return report
	}
	detail := strings.TrimSpace(string(out))
	if err != nil {
		if detail != "" {
			detail = err.Error() + ": " + detail
		} else {
			detail = err.Error()
		}
	}
	if detail == "" {
		detail = "Патчер не вернул результат."
	}
	return antigravityReport{State: "unknown", Rc: 1, Detail: detail}
}

func antigravityRun(ctx context.Context, action string) antigravityReport {
	app, err := antigravityApp()
	if err != nil {
		return antigravityReport{State: "missing", Rc: 0}
	}
	binary := antigravityBinary(app)
	version := antigravityVersion(app)
	report := antigravityReport{Path: binary, Version: version, Rc: 1}
	if info, err := os.Stat(binary); err != nil || info.IsDir() {
		report.State = "missing"
		return report
	}
	python := antigravityPython()
	if python == "" {
		report.State = "error"
		report.Detail = "Нужен Python 3: установите Command Line Tools Xcode."
		return report
	}
	bridge, bundled, err := antigravityPatcherAssets()
	if err != nil {
		report.State = "error"
		report.Detail = err.Error()
		return report
	}
	var last antigravityReport
	for _, engine := range antigravityEngines(bundled) {
		result := antigravityInvoke(ctx, python, bridge, engine.script, action, binary)
		result.Path = binary
		result.Version = version
		result.Engine = engine.kind
		result.EngineAt = engine.installedAt
		if result.State == "unknown" && result.Rc != 0 && engine.kind == "downloaded" {
			// A broken downloaded engine must never block patching.
			last = result
			continue
		}
		if result.Rc != 0 {
			if hint := antigravityFailureHint(result.Detail); hint != "" {
				result.Detail = hint
			}
		}
		return result
	}
	if last.Rc != 0 {
		if hint := antigravityFailureHint(last.Detail); hint != "" {
			last.Detail = hint
		}
	}
	return last
}

func antigravityCheckUpdate(ctx context.Context) antigravityReport {
	report := antigravityReport{Rc: 0, State: "update"}
	pin, err := antigravityPinInfo()
	if err != nil {
		report.Update = "error"
		report.Detail = "Не удалось прочитать данные патчера: " + err.Error()
		return report
	}
	latest, err := antigravityLatestCommit(ctx, pin)
	if err != nil {
		report.Update = "error"
		report.Detail = "Не удалось проверить обновление: " + err.Error()
		return report
	}
	report.Commit = latest.SHA
	if latest.SHA == antigravityActiveCommit(pin) {
		report.Update = "current"
	} else {
		report.Update = "available"
	}
	return report
}

func antigravityApplyUpdate(ctx context.Context) antigravityReport {
	report := antigravityReport{Rc: 1, State: "update"}
	pin, err := antigravityPinInfo()
	if err != nil {
		report.Update = "error"
		report.Detail = "Не удалось прочитать данные патчера: " + err.Error()
		return report
	}
	latest, err := antigravityLatestCommit(ctx, pin)
	if err != nil {
		report.Update = "error"
		report.Detail = "Не удалось проверить обновление: " + err.Error()
		return report
	}
	report.Commit = latest.SHA
	if latest.SHA == antigravityActiveCommit(pin) {
		report.Update = "current"
		report.Rc = 0
		return report
	}
	raw, err := antigravityDownloadScript(ctx, pin, latest.SHA)
	if err != nil {
		report.Update = "error"
		report.Detail = "Не удалось скачать патчер: " + err.Error()
		return report
	}
	state, err := antigravityInstallUpdate(latest, raw)
	if err != nil {
		report.Update = "error"
		report.Detail = "Обновление не установлено: " + err.Error()
		return report
	}
	report.Update = "installed"
	report.Rc = 0
	report.Engine = "downloaded"
	report.EngineAt = state.InstalledAt
	return report
}

func antigravityCommand(ctx context.Context, action string) int {
	if runtime.GOOS != "darwin" {
		fmt.Fprintln(os.Stderr, "Antigravity patching is available on macOS only")
		return 1
	}
	var report antigravityReport
	switch action {
	case "status", "patch", "restore":
		report = antigravityRun(ctx, action)
	case "check-update":
		report = antigravityCheckUpdate(ctx)
	case "update":
		report = antigravityApplyUpdate(ctx)
	default:
		fmt.Fprintln(os.Stderr, "unknown antigravity action:", action)
		return 2
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(report); err != nil {
		return 1
	}
	return 0
}
