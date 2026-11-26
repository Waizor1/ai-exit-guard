package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The bundled patcher records the upstream commit it came from. The update
// button downloads manager.py from that repository at the newest commit that
// touched it, stores it outside the signed bundle and uses it first. A copy
// that fails to run never blocks patching: Guard falls back to the bundled one.
const antigravityAPI = "https://api.github.com"

type antigravityPin struct {
	Repo   string `json:"repo"`
	Path   string `json:"path"`
	Commit string `json:"commit"`
}

type antigravityEngineState struct {
	Commit      string `json:"commit"`
	InstalledAt string `json:"installedAt"`
}

type antigravityCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Committer struct {
			Date string `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

func antigravityAssetsDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "antigravity"), nil
}

func antigravityPinInfo() (antigravityPin, error) {
	var pin antigravityPin
	dir, err := antigravityAssetsDir()
	if err != nil {
		return pin, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		return pin, err
	}
	if err := json.Unmarshal(data, &pin); err != nil {
		return pin, err
	}
	if pin.Repo == "" || pin.Path == "" {
		return pin, errors.New("patcher pin is incomplete")
	}
	return pin, nil
}

// antigravityInstallDir holds the downloaded engine and its provenance.
func antigravityInstallDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "AI Exit Guard", "antigravity")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func antigravityDownloadedEngine() (string, antigravityEngineState, bool) {
	dir, err := antigravityInstallDir()
	if err != nil {
		return "", antigravityEngineState{}, false
	}
	script := filepath.Join(dir, "antigravity_patcher.py")
	if info, err := os.Stat(script); err != nil || info.IsDir() {
		return "", antigravityEngineState{}, false
	}
	var state antigravityEngineState
	if data, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	return script, state, true
}

func antigravityGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AI-Exit-Guard")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	return body, nil
}

func antigravityLatestCommit(ctx context.Context, pin antigravityPin) (antigravityCommit, error) {
	url := fmt.Sprintf("%s/repos/%s/commits?path=%s&per_page=1", antigravityAPI, pin.Repo, pin.Path)
	data, err := antigravityGet(ctx, url)
	if err != nil {
		return antigravityCommit{}, err
	}
	var commits []antigravityCommit
	if err := json.Unmarshal(data, &commits); err != nil {
		return antigravityCommit{}, err
	}
	if len(commits) == 0 {
		return antigravityCommit{}, errors.New("в репозитории нет коммитов для патчера")
	}
	return commits[0], nil
}

func antigravityDownloadScript(ctx context.Context, pin antigravityPin, commit string) ([]byte, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", pin.Repo, commit, pin.Path)
	data, err := antigravityGet(ctx, url)
	if err != nil {
		return nil, err
	}
	if len(data) < 1024 || !strings.Contains(string(data[:1024]), "python") {
		return nil, errors.New("скачанный файл не похож на скрипт патчера")
	}
	return data, nil
}

// antigravityInstallUpdate replaces the downloaded engine atomically. The
// bundled copy stays untouched and remains the fallback.
func antigravityInstallUpdate(commit antigravityCommit, raw []byte) (antigravityEngineState, error) {
	dir, err := antigravityInstallDir()
	if err != nil {
		return antigravityEngineState{}, err
	}
	script := filepath.Join(dir, "antigravity_patcher.py")
	temp, err := os.CreateTemp(dir, "antigravity_patcher-*.py")
	if err != nil {
		return antigravityEngineState{}, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return antigravityEngineState{}, err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return antigravityEngineState{}, err
	}
	if err := temp.Close(); err != nil {
		return antigravityEngineState{}, err
	}
	if err := os.Rename(tempName, script); err != nil {
		return antigravityEngineState{}, err
	}
	state := antigravityEngineState{
		Commit:      commit.SHA,
		InstalledAt: time.Now().Format("2006-01-02 15:04"),
	}
	payload, _ := json.MarshalIndent(state, "", "  ")
	if err := writeFileAtomic(filepath.Join(dir, "state.json"), payload); err != nil {
		os.Remove(script)
		return antigravityEngineState{}, err
	}
	return state, nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func commandWithEnv(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	return cmd
}

// antigravityActiveCommit returns the upstream commit of the active engine.
func antigravityActiveCommit(pin antigravityPin) string {
	if _, state, ok := antigravityDownloadedEngine(); ok {
		return state.Commit
	}
	return pin.Commit
}
