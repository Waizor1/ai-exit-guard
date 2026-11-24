package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var t3ReleaseID = regexp.MustCompile("^[a-f0-9]{64}$")

func readReleaseRecord(path string, dest any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
		return errors.New("T3 ещё не завершил установку Antigravity")
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, dest) != nil {
		return errors.New("T3 вернул нечитаемую запись об установке Antigravity")
	}
	return nil
}

func activeAntigravity(base string) (string, string, error) {
	var active struct{ ReleaseID string }
	if err := readReleaseRecord(filepath.Join(base, "active.json"), &active); err != nil {
		return "", "", err
	}
	if !t3ReleaseID.MatchString(active.ReleaseID) {
		return "", "", errors.New("T3 указал неизвестный формат версии Antigravity")
	}
	dir := filepath.Join(base, "versions", active.ReleaseID)
	for _, folder := range []string{base, filepath.Dir(dir), dir} {
		st, err := os.Lstat(folder)
		if err != nil || !st.IsDir() {
			return "", "", errors.New("каталог активной версии Antigravity недоступен")
		}
	}
	var record struct {
		ReleaseID, Version string
		Executable         struct {
			Name  string
			Bytes int64
		}
	}
	if err := readReleaseRecord(filepath.Join(dir, ".install-complete.json"), &record); err != nil {
		return "", "", err
	}
	name := record.Executable.Name
	if record.ReleaseID != active.ReleaseID || record.Version == "" || name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "\r\n\\") {
		return "", "", errors.New("сведения об активной версии Antigravity не совпадают")
	}
	path := filepath.Join(dir, name)
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 || st.Size() == 0 || st.Size() != record.Executable.Bytes {
		return "", "", errors.New("файл Antigravity изменился или обновление ещё идёт")
	}
	return path, record.Version, nil
}

// Use a disposable profile for the same ACP initialize exchange T3 performs.
// The probe cannot send traffic, launch a login browser or access saved account settings via HOME.
func probeAntigravity(ctx context.Context, path, version string) error {
	tmp, err := os.MkdirTemp("", "guard-acp-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network-outbound)", path, "acp")
	cmd.Dir = tmp
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + tmp, "TMPDIR=" + tmp, "XDG_CONFIG_HOME=" + tmp, "XDG_DATA_HOME=" + tmp, "XDG_CACHE_HOME=" + tmp, "BROWSER=/usr/bin/false"}
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return errors.New("Antigravity не запускается")
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	_, err = io.WriteString(in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{}}}`+"\n")
	if err != nil {
		return errors.New("Antigravity закрыл канал проверки")
	}
	var reply struct {
		ID     int
		Result struct {
			ProtocolVersion   int
			AgentInfo         struct{ Name, Version string }
			AgentCapabilities struct{ LoadSession bool }
			AuthMethods       []struct{ ID string }
		}
	}
	if err := json.NewDecoder(io.LimitReader(out, 1<<20)).Decode(&reply); err != nil {
		return errors.New("Antigravity не ответил на проверку запуска T3")
	}
	r := reply.Result
	if reply.ID == 1 && (r.ProtocolVersion == 1 || r.ProtocolVersion == 2) && r.AgentInfo.Name == "Antigravity ACP Server" && r.AgentInfo.Version == version && r.AgentCapabilities.LoadSession {
		for _, method := range r.AuthMethods {
			if method.ID == "oauth-personal" {
				return nil
			}
		}
	}
	return errors.New("эта версия Antigravity не подтвердила совместимость с T3")
}

func checkedAntigravity(ctx context.Context) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	root := os.Getenv("T3CODE_HOME")
	if root == "" {
		root = filepath.Join(home, ".t3")
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("T3CODE_HOME должен быть абсолютным путём")
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	base := filepath.Join(root, "tools", "antigravity-acp", "darwin-"+arch)
	path, version, err := activeAntigravity(base)
	if err != nil {
		return "", err
	}
	if err := probeAntigravity(ctx, path, version); err != nil {
		return "", err
	}
	return path, nil
}
