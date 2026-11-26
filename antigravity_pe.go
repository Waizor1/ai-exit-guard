package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Windows builds carry the same hasValidAuth gate as macOS, but as a PE image
// and without code signing. The gate is matched only inside executable
// sections, exactly once, and the original binary is kept next to it.

type peSection struct{ start, end int }

type peGate struct {
	plain   []byte
	mask    []bool
	patched []byte
}

// parseGatePattern turns "80 78 08 00 74 ?? ..." into bytes plus a wildcard mask.
func parseGatePattern(pattern string) ([]byte, []bool) {
	fields := strings.Fields(pattern)
	out := make([]byte, 0, len(fields))
	mask := make([]bool, 0, len(fields))
	for _, field := range fields {
		if field == "??" || field == "?" {
			out = append(out, 0)
			mask = append(mask, true)
			continue
		}
		var b byte
		if _, err := fmt.Sscanf(field, "%02x", &b); err != nil {
			panic("bad gate byte: " + field)
		}
		out = append(out, b)
		mask = append(mask, false)
	}
	return out, mask
}

// manager gate: cmp byte[rax+8],0 ; je -> mov byte[rax+8],1 ; nop nop
var managerPEGate = func() peGate {
	plain, mask := parseGatePattern("80 78 08 00 74 ?? 48 8b 54 24 70 48 89 50 60")
	patched, _ := parseGatePattern("c6 40 08 01 90 90 48 8b 54 24 70 48 89 50 60")
	return peGate{plain: plain, mask: mask, patched: patched}
}()

func peRanges(data []byte) ([]peSection, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, errors.New("не PE-образ")
	}
	lfanew := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if lfanew <= 0 || lfanew+24 > len(data) || string(data[lfanew:lfanew+4]) != "PE\x00\x00" {
		return nil, errors.New("повреждён PE-заголовок")
	}
	sections := int(binary.LittleEndian.Uint16(data[lfanew+6:]))
	optSize := int(binary.LittleEndian.Uint16(data[lfanew+20:]))
	base := lfanew + 24 + optSize
	var out []peSection
	for i := 0; i < sections; i++ {
		header := base + i*40
		if header+40 > len(data) {
			return nil, errors.New("повреждена таблица секций PE")
		}
		rawSize := int(binary.LittleEndian.Uint32(data[header+16:]))
		rawPtr := int(binary.LittleEndian.Uint32(data[header+20:]))
		flags := binary.LittleEndian.Uint32(data[header+36:])
		if flags&0x20000000 == 0 || rawSize == 0 {
			continue
		}
		start := rawPtr
		end := rawPtr + rawSize
		if start < 0 || start >= len(data) {
			continue
		}
		if end > len(data) {
			end = len(data)
		}
		if end > start {
			out = append(out, peSection{start: start, end: end})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("в PE нет исполняемых секций")
	}
	return out, nil
}

func peFind(pattern []byte, mask []bool, data []byte, ranges []peSection) []int {
	var hits []int
	for _, r := range ranges {
		for pos := r.start; pos+len(pattern) <= r.end; pos++ {
			ok := true
			for i := range pattern {
				if !mask[i] && data[pos+i] != pattern[i] {
					ok = false
					break
				}
			}
			if ok {
				hits = append(hits, pos)
			}
		}
	}
	return hits
}

func peGateState(data []byte) (string, int, error) {
	ranges, err := peRanges(data)
	if err != nil {
		return "", 0, err
	}
	plain := peFind(managerPEGate.plain, managerPEGate.mask, data, ranges)
	patched := peFind(managerPEGate.patched, make([]bool, len(managerPEGate.patched)), data, ranges)
	if len(plain) > 0 && len(patched) > 0 {
		return "", 0, errors.New("в файле найдены и патченная, и оригинальная сигнатуры")
	}
	if len(plain) > 1 || len(patched) > 1 {
		return "", 0, errors.New("сигнатура встречается несколько раз — патч отменён")
	}
	if len(plain) == 1 {
		return "unpatched", plain[0], nil
	}
	if len(patched) == 1 {
		return "patched", patched[0], nil
	}
	return "unsupported", 0, errors.New("сигнатура не найдена: версия Antigravity не поддерживается")
}

// antigravityPECandidates finds language_server.exe under the usual Windows
// install roots. AI_GUARD_ANTIGRAVITY_APP overrides the search for tests.
func antigravityPECandidates() []string {
	if custom := os.Getenv("AI_GUARD_ANTIGRAVITY_APP"); custom != "" {
		info, err := os.Stat(custom)
		if err == nil && !info.IsDir() {
			return []string{custom}
		}
		if err == nil && info.IsDir() {
			return []string{filepath.Join(custom, "resources", "bin", "language_server.exe")}
		}
	}
	var roots []string
	for _, key := range []string{"LOCALAPPDATA", "ProgramW6432", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "APPDATA"} {
		if value := os.Getenv(key); value != "" {
			roots = append(roots, value, filepath.Join(value, "Programs"))
		}
	}
	if profile := os.Getenv("USERPROFILE"); profile != "" {
		roots = append(roots, filepath.Join(profile, "scoop", "apps"))
	}
	var hits []string
	for _, root := range roots {
		patterns := []string{
			filepath.Join(root, "*ntigravity*", "resources", "bin", "language_server.exe"),
			filepath.Join(root, "*ntigravity*", "*", "resources", "bin", "language_server.exe"),
		}
		for _, pattern := range patterns {
			matches, _ := filepath.Glob(pattern)
			hits = append(hits, matches...)
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i] < hits[j] })
	return hits
}

func antigravityPELocate() (string, error) {
	hits := antigravityPECandidates()
	if len(hits) == 0 {
		return "", os.ErrNotExist
	}
	return hits[0], nil
}

func antigravityPEVersion(binary string) string {
	// <app>\resources\bin\language_server.exe
	app := filepath.Dir(filepath.Dir(filepath.Dir(binary)))
	for _, name := range []string{filepath.Join("app", "package.json"), "package.json"} {
		data, err := os.ReadFile(filepath.Join(app, "resources", name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "\"version\"") {
				if parts := strings.Split(line, "\""); len(parts) >= 4 {
					return parts[3]
				}
			}
		}
	}
	return ""
}

func antigravityPERun(action string) antigravityReport {
	report := antigravityReport{Rc: 1, Engine: "native"}
	binary, err := antigravityPELocate()
	if err != nil {
		report.State = "missing"
		report.Rc = 0
		return report
	}
	report.Path = binary
	report.Version = antigravityPEVersion(binary)
	data, err := os.ReadFile(binary)
	if err != nil {
		report.State = "error"
		report.Detail = "Не удалось прочитать language_server.exe: " + err.Error()
		return report
	}
	state, offset, stateErr := peGateState(data)
	if stateErr != nil && state == "" {
		report.State = "unknown"
		report.Detail = stateErr.Error()
		return report
	}
	report.State = state
	if state == "unsupported" {
		report.Rc = 0
		report.Detail = stateErr.Error()
		return report
	}
	if stateErr != nil {
		report.Detail = stateErr.Error()
		return report
	}
	switch action {
	case "status":
		report.Rc = 0
	case "patch":
		if state == "patched" {
			report.Rc = 0
			break
		}
		backup := binary + ".agybak"
		if err := antigravityWriteBackup(binary, backup, data); err != nil {
			report.Detail = err.Error()
			break
		}
		patched := make([]byte, len(data))
		copy(patched, data)
		copy(patched[offset:], managerPEGate.patched)
		if err := antigravityWriteFile(binary, patched); err != nil {
			report.Detail = antigravityPEWriteHint(err)
			break
		}
		check, err := os.ReadFile(binary)
		if err != nil {
			report.Detail = "Не удалось перечитать файл: " + err.Error()
			break
		}
		if after, _, err := peGateState(check); err != nil || after != "patched" {
			_ = antigravityWriteFile(binary, data)
			report.State = "unpatched"
			report.Detail = "Проверка после записи не прошла, изменения отменены"
			break
		}
		report.State = "patched"
		report.Rc = 0
	case "restore":
		if state != "patched" {
			report.Rc = 0
			break
		}
		backup := binary + ".agybak"
		original, err := os.ReadFile(backup)
		if err != nil {
			report.Detail = "Нет резервной копии для восстановления"
			break
		}
		if backupState, _, err := peGateState(original); err != nil || backupState != "unpatched" {
			report.Detail = "Резервная копия не является чистой сборкой — восстановление отменено"
			break
		}
		if err := antigravityWriteFile(binary, original); err != nil {
			report.Detail = antigravityPEWriteHint(err)
			break
		}
		report.State = "unpatched"
		report.Rc = 0
	}
	return report
}

func antigravityWriteBackup(binary, backup string, data []byte) error {
	if _, err := os.Stat(backup); err == nil {
		existing, err := os.ReadFile(backup)
		if err != nil {
			return errors.New("резервная копия существует, но не читается")
		}
		if state, _, err := peGateState(existing); err != nil || state != "unpatched" {
			return errors.New("резервная копия не является чистой сборкой — патч отменён")
		}
		return nil
	}
	return antigravityWriteFile(backup, data)
}

func antigravityWriteFile(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".agy-write-*")
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
	if err := os.Chmod(name, 0o755); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// antigravityPEWriteHint turns raw Windows file errors into an instruction.
func antigravityPEWriteHint(err error) string {
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "being used by another process"), strings.Contains(text, "sharing violation"):
		return "Закройте Antigravity и повторите: файл занят запущенным приложением."
	case strings.Contains(text, "access is denied"), strings.Contains(text, "permission denied"):
		return "Нет прав на запись: запустите AI Exit Guard от имени администратора."
	}
	return "Не удалось записать language_server.exe: " + err.Error()
}
