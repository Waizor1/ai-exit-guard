package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const appUpdateRepo = "Waizor1/ai-exit-guard"

type appUpdateReport struct {
	State      string `json:"state"`
	Current    string `json:"current,omitempty"`
	Latest     string `json:"latest,omitempty"`
	Tag        string `json:"tag,omitempty"`
	AssetName  string `json:"assetName,omitempty"`
	AssetURL   string `json:"assetUrl,omitempty"`
	ReleaseURL string `json:"releaseUrl,omitempty"`
	Path       string `json:"path,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Rc         int    `json:"rc"`
}

type githubRelease struct {
	TagName    string        `json:"tag_name"`
	Name       string        `json:"name"`
	HTMLURL    string        `json:"html_url"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type parsedVersion struct {
	nums [3]int
	pre  string
}

func parseAppVersion(raw string) (parsedVersion, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return parsedVersion{}, false
	}
	base, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(base, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return parsedVersion{}, false
	}
	var v parsedVersion
	v.pre = strings.ToLower(strings.TrimSpace(pre))
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return parsedVersion{}, false
		}
		v.nums[i] = n
	}
	return v, true
}

// compareAppVersions returns -1 if a < b, 0 if a == b, +1 if a > b.
func compareAppVersions(a, b string) int {
	va, oka := parseAppVersion(a)
	vb, okb := parseAppVersion(b)
	if !oka || !okb {
		return strings.Compare(strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v"))
	}
	for i := 0; i < 3; i++ {
		if va.nums[i] < vb.nums[i] {
			return -1
		}
		if va.nums[i] > vb.nums[i] {
			return 1
		}
	}
	if va.pre == vb.pre {
		return 0
	}
	if va.pre == "" {
		return 1
	}
	if vb.pre == "" {
		return -1
	}
	return strings.Compare(va.pre, vb.pre)
}

func selectReleaseAsset(assets []githubAsset, goos string) (asset githubAsset, sumsURL string, ok bool) {
	var fallback githubAsset
	var hasFallback bool
	for _, a := range assets {
		lower := strings.ToLower(a.Name)
		if lower == "sha256sums.txt" {
			sumsURL = a.BrowserDownloadURL
			continue
		}
		switch goos {
		case "darwin":
			if strings.HasSuffix(lower, ".dmg") {
				asset = a
				ok = true
			} else if strings.Contains(lower, "app update") && strings.HasSuffix(lower, ".zip") {
				fallback = a
				hasFallback = true
			}
		case "windows":
			if strings.Contains(lower, "windows") && strings.HasSuffix(lower, ".zip") {
				asset = a
				ok = true
			}
		}
	}
	if !ok && hasFallback {
		return fallback, sumsURL, true
	}
	return asset, sumsURL, ok
}

func parseSHA256Sums(body, filename string) string {
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := strings.TrimPrefix(fields[1], "*")
			if name == filename && len(fields[0]) == 64 {
				return strings.ToLower(fields[0])
			}
		}
	}
	return ""
}

func appUpdateFetchReleases(ctx context.Context) ([]githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=10", appUpdateRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AI-Exit-Guard")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	var releases []githubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, err
	}
	return releases, nil
}

func appUpdateLatest(ctx context.Context, current string) (appUpdateReport, *githubRelease, githubAsset, string) {
	report := appUpdateReport{State: "error", Current: strings.TrimPrefix(strings.TrimSpace(current), "v"), Rc: 1}
	releases, err := appUpdateFetchReleases(ctx)
	if err != nil {
		report.Detail = "Не удалось проверить обновления: " + err.Error()
		return report, nil, githubAsset{}, ""
	}
	var best *githubRelease
	var bestAsset githubAsset
	var bestSums string
	for i := range releases {
		rel := &releases[i]
		if rel.Draft {
			continue
		}
		asset, sums, ok := selectReleaseAsset(rel.Assets, runtime.GOOS)
		if !ok {
			continue
		}
		if best == nil || compareAppVersions(rel.TagName, best.TagName) > 0 {
			best = rel
			bestAsset = asset
			bestSums = sums
		}
	}
	if best == nil {
		report.State = "current"
		report.Latest = report.Current
		report.Rc = 0
		return report, nil, githubAsset{}, ""
	}
	report.Tag = best.TagName
	report.Latest = strings.TrimPrefix(best.TagName, "v")
	report.AssetName = bestAsset.Name
	report.AssetURL = bestAsset.BrowserDownloadURL
	report.ReleaseURL = best.HTMLURL
	report.Rc = 0
	if compareAppVersions(report.Latest, report.Current) > 0 {
		report.State = "available"
	} else {
		report.State = "current"
	}
	return report, best, bestAsset, bestSums
}

func appUpdateDownloadFile(ctx context.Context, url, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "AI-Exit-Guard")
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("сервер ответил %s", resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 256<<20)); err != nil {
		f.Close()
		os.Remove(dest)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(dest)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func appUpdateVerifySums(ctx context.Context, sumsURL, filename, actualHash string) error {
	if sumsURL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "AI-Exit-Guard")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return err
	}
	expected := parseSHA256Sums(string(body), filename)
	if expected == "" {
		return nil
	}
	if !strings.EqualFold(expected, actualHash) {
		return errors.New("контрольная сумма SHA-256 не совпала — обновление отменено")
	}
	return nil
}

func appUpdateInstall(ctx context.Context, current string) appUpdateReport {
	report, _, asset, sumsURL := appUpdateLatest(ctx, current)
	if report.Rc != 0 {
		return report
	}
	if report.State != "available" {
		return report
	}
	stageDir := filepath.Join(os.TempDir(), "ai-exit-guard-update-"+sanitizeTag(report.Tag))
	_ = os.RemoveAll(stageDir)
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		report.State = "error"
		report.Rc = 1
		report.Detail = "Не удалось создать временную папку: " + err.Error()
		return report
	}
	dest := filepath.Join(stageDir, filepath.Base(asset.Name))
	actualHash, err := appUpdateDownloadFile(ctx, asset.BrowserDownloadURL, dest)
	if err != nil {
		report.State = "error"
		report.Rc = 1
		report.Detail = "Не удалось скачать обновление: " + err.Error()
		return report
	}
	if err := appUpdateVerifySums(ctx, sumsURL, asset.Name, actualHash); err != nil {
		_ = os.Remove(dest)
		report.State = "error"
		report.Rc = 1
		report.Detail = err.Error()
		return report
	}
	report.Path = dest
	switch runtime.GOOS {
	case "darwin":
		if strings.HasSuffix(strings.ToLower(dest), ".dmg") {
			mountPoint := filepath.Join(stageDir, "mnt")
			_ = os.MkdirAll(mountPoint, 0o700)
			if err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mountPoint, dest).Run(); err == nil {
				matches, _ := filepath.Glob(filepath.Join(mountPoint, "*.pkg"))
				if len(matches) > 0 {
					if err := exec.CommandContext(ctx, "/usr/bin/open", matches[0]).Run(); err == nil {
						report.State = "installing"
						report.Detail = "Установщик обновления открыт."
						report.Rc = 0
						return report
					}
				}
			}
		}
		if err := exec.CommandContext(ctx, "/usr/bin/open", dest).Run(); err != nil {
			report.State = "error"
			report.Rc = 1
			report.Detail = "Не удалось открыть образ обновления: " + err.Error()
			return report
		}
		report.State = "installing"
		report.Detail = "Образ обновления открыт."
		report.Rc = 0
		return report
	case "windows":
		extractDir := filepath.Join(stageDir, "files")
		if err := extractZipSafe(dest, extractDir); err != nil {
			report.State = "error"
			report.Rc = 1
			report.Detail = "Не удалось распаковать архив обновления: " + err.Error()
			return report
		}
		exe, err := os.Executable()
		if err != nil {
			report.State = "error"
			report.Rc = 1
			report.Detail = "Не удалось определить папку установки: " + err.Error()
			return report
		}
		installDir := filepath.Dir(exe)
		scriptPath := filepath.Join(stageDir, "apply-update.cmd")
		script := fmt.Sprintf("@echo off\r\ntimeout /t 2 /nobreak >nul\r\nxcopy /E /Y /I \"%s\\*\" \"%s\\\" >nul\r\nstart \"\" \"%s\\AI Exit Guard.exe\"\r\n", extractDir, installDir, installDir)
		if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
			report.State = "error"
			report.Rc = 1
			report.Detail = "Не удалось подготовить скрипт обновления: " + err.Error()
			return report
		}
		cmd := exec.Command("cmd.exe", "/C", "start", "", "/min", scriptPath)
		if err := cmd.Start(); err != nil {
			report.State = "error"
			report.Rc = 1
			report.Detail = "Не удалось запустить установку обновления: " + err.Error()
			return report
		}
		report.State = "installing"
		report.Detail = "Обновление скачано, приложение перезапустится."
		report.Rc = 0
		return report
	default:
		report.State = "downloaded"
		report.Detail = "Обновление сохранено: " + dest
		report.Rc = 0
		return report
	}
}

func sanitizeTag(tag string) string {
	var b strings.Builder
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "latest"
	}
	return b.String()
}

func extractZipSafe(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	cleanDest := filepath.Clean(destDir) + string(os.PathSeparator)
	for _, f := range r.File {
		target := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanDest) && filepath.Clean(target) != filepath.Clean(destDir) {
			return errors.New("недопустимый путь в архиве")
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(rc, 256<<20))
		closeErr := out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func appUpdateCommand(ctx context.Context, action, current string) int {
	var report appUpdateReport
	switch action {
	case "check":
		report, _, _, _ = appUpdateLatest(ctx, current)
	case "install":
		report = appUpdateInstall(ctx, current)
	default:
		fmt.Fprintln(os.Stderr, "unknown app-update action:", action)
		return 2
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return 1
	}
	return 0
}
