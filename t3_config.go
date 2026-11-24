package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func restoreT3Routes(path, bin string) error {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("файл настроек T3 недоступен")
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	d := json.NewDecoder(bytes.NewReader(old))
	d.UseNumber()
	if err = d.Decode(&doc); err != nil {
		return err
	}
	providers, ok := doc["providerInstances"].(map[string]any)
	if !ok {
		return errors.New("формат настроек T3 не распознан")
	}
	changed := false
	installed := "/Applications/AI Exit Guard.app/Contents/Resources"
	for id, client := range map[string]string{"codex": "codex", "claudeAgent": "claude", "antigravity": "antigravity"} {
		record, _ := providers[id].(map[string]any)
		if record == nil {
			continue
		}
		cfg, _ := record["config"].(map[string]any)
		current, _ := cfg["binaryPath"].(string)
		name := filepath.Base(current)
		owned := (filepath.Dir(current) == installed || filepath.Dir(current) == bin) && (name == "guarded-"+client || (id == "antigravity" && name == "agy"))
		if owned {
			delete(cfg, "binaryPath")
			changed = true
		}
		list, ok := record["environment"].([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(list))
		for _, entry := range list {
			row, _ := entry.(map[string]any)
			key, _ := row["name"].(string)
			value, _ := row["value"].(string)
			switch strings.ToUpper(key) {
			case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
				if value == "http://127.0.0.1:39178" {
					changed = true
					continue
				}
			}
			kept = append(kept, entry)
		}
		if len(kept) != len(list) {
			record["environment"] = kept
		}
	}
	if !changed {
		return nil
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guard-t3-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(append(data, '\n')); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, old) {
		return errors.New("настройки T3 изменились, повторите действие")
	}
	return os.Rename(tmp.Name(), path)
}
