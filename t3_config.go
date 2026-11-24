package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func configureT3(path, bin string, migrateOnly bool) error {
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
	for id, client := range map[string]string{"codex": "codex", "claudeAgent": "claude", "antigravity": "antigravity"} {
		record, ok := providers[id].(map[string]any)
		if !ok {
			continue
		}
		cfg, ok := record["config"].(map[string]any)
		if !ok {
			if record["config"] != nil {
				return errors.New("неизвестный формат провайдера")
			}
			cfg = map[string]any{}
		}
		previous := filepath.Join(bin, "guarded-"+client)
		if migrateOnly && (client != "antigravity" || cfg["binaryPath"] != previous) {
			continue
		}
		launcher := previous
		// T3 accepts external Antigravity launchers only under a recognized CLI name.
		if client == "antigravity" {
			launcher = filepath.Join(bin, "agy")
		}
		info, err := os.Stat(launcher)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("нет программы запуска %s", client)
		}
		if cfg["binaryPath"] == launcher {
			continue
		}
		if cfg["binaryPath"] != nil && cfg["binaryPath"] != "" && cfg["binaryPath"] != previous {
			return fmt.Errorf("у %s уже задан другой путь. Сохраните его и выберите Guard в настройках T3", client)
		}
		cfg["binaryPath"] = launcher
		record["config"] = cfg
		changed = true
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
