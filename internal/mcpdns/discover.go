// Package mcpdns identifies exact public remote MCP hosts eligible for scoped DNS repair.
package mcpdns

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Registry metadata is refreshed offline by tools/refresh_catalog.py.
//
//go:embed catalog.tsv
var snapshot string

var catalog = func() map[string]string {
	hosts := make(map[string]string)
	for row := range strings.Lines(snapshot) {
		if strings.HasPrefix(row, "#") {
			continue
		}
		h, publisher, ok := strings.Cut(strings.TrimSpace(row), "\t")
		if ok {
			hosts[h] = publisher
		}
	}
	return hosts
}()

func candidate(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if catalog[h] == "" || !(strings.EqualFold(u.Host, h) || strings.EqualFold(u.Host, h+":443")) {
		return ""
	}
	return h
}

const maxConfig = 2 << 20

func readConfig(root *os.Root, path string) []byte {
	s, err := root.Lstat(path)
	if err != nil || !s.Mode().IsRegular() || s.Size() > maxConfig {
		return nil
	}
	f, err := root.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !os.SameFile(s, st) {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err != nil || len(b) > maxConfig {
		return nil
	}
	return b
}

type entry struct {
	URL       string
	HTTPURL   string
	ServerURL string
	Disabled  bool
	Type      string
	Command   json.RawMessage
	Enabled   *bool
}

func jsonHosts(b []byte, openCode bool, add func(string)) {
	var cfg struct {
		MCPServers map[string]entry
		MCP        map[string]entry
	}
	if json.Unmarshal(b, &cfg) != nil {
		return
	}
	entries := cfg.MCPServers
	if openCode {
		entries = cfg.MCP
	}
	if len(entries) > 256 {
		return
	}
	for _, s := range entries {
		if s.Disabled || s.Enabled != nil && !*s.Enabled || len(s.Command) > 0 {
			continue
		}
		if openCode && s.Type != "remote" {
			continue
		}
		switch s.Type {
		case "", "remote", "http", "sse", "streamable-http":
			add(s.URL)
			add(s.HTTPURL)
			add(s.ServerURL)
		}
	}
}

// Only unambiguous simple TOML server tables and literal URL assignments are supported.
var section = regexp.MustCompile(`^\[mcp_servers\.(?:[a-zA-Z0-9_-]+|"[a-zA-Z0-9_.-]+"|'[a-zA-Z0-9_.-]+')\]\s*(?:#.*)?$`)
var urlLine = regexp.MustCompile(`^url\s*=\s*(?:"([^"\\]*)"|'([^']*)')\s*(?:#.*)?$`)
var disabledLine = regexp.MustCompile(`^enabled\s*=\s*false\s*(?:#.*)?$`)
var commandLine = regexp.MustCompile(`^command\s*=`)

func tomlHosts(b []byte, add func(string)) {
	if bytes.Contains(b, []byte(`"""`)) || bytes.Contains(b, []byte("'''")) {
		return
	}
	count := 0
	var pending []string
	var raw string
	var server, skip bool
	flush := func() {
		if server && !skip {
			pending = append(pending, raw)
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			flush()
			server = section.MatchString(line)
			if server {
				count++
				if count > 256 {
					return
				}
			}
			skip = false
			raw = ""
			continue
		}
		if !server {
			continue
		}
		if disabledLine.MatchString(line) || commandLine.MatchString(line) {
			skip = true
		}
		if m := urlLine.FindStringSubmatch(line); m != nil {
			raw = m[1] + m[2]
		}
	}
	flush()
	for _, u := range pending {
		add(u)
	}
}

// Discover returns sorted exact catalog hosts from bounded per-user configs. It performs no network requests.
func Discover(home string) []string {
	if !filepath.IsAbs(home) {
		return nil
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil
	}
	defer root.Close()
	seen := make(map[string]bool)
	add := func(raw string) {
		if h := candidate(raw); h != "" {
			seen[h] = true
		}
	}
	for _, p := range []string{".claude.json", "Library/Application Support/Claude/claude_desktop_config.json", ".gemini/settings.json", ".gemini/antigravity/mcp_config.json", ".gemini/config/mcp_config.json", ".config/opencode/opencode.json", ".config/opencode/opencode.jsonc"} {
		b := readConfig(root, p)
		if strings.HasSuffix(p, ".jsonc") {
			b = cleanJSONC(b)
		}
		jsonHosts(b, strings.Contains(p, "/opencode/"), add)
	}
	tomlHosts(readConfig(root, ".codex/config.toml"), add)
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}
