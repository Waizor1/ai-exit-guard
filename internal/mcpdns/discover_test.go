package mcpdns

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDiscover(t *testing.T) {
	home := t.TempDir()
	configs := map[string]string{
		".claude.json":          `{"mcpServers":{"linear":{"url":"https://mcp.linear.app/mcp?secret=x"},"corp":{"url":"https://corp.private/mcp"},"disabled":{"type":"stdio","url":"https://mcp.sentry.dev/mcp"}}}`,
		".gemini/settings.json": `{"mcpServers":{"figma":{"httpUrl":"https://MCP.FIGMA.COM:443/mcp"}}}`,
		".config/opencode/opencode.jsonc": `{/* old server */ "mcp": { "exa": {"type":"remote","url":"https://mcp.exa.ai/mcp?q=//","enabled":true,}, // ending
 "disabled":{"type":"remote","url":"https://mcp.sentry.dev","enabled":false}, },}`,
		".codex/config.toml": `[mcp_servers."ctx"]
url = "https://mcp.context7.com/mcp" # bounded literal
[mcp_servers.skip]
url = 'https://mcp.notion.com'
enabled = false
[mcp_servers.local]
command = "example"
url = 'https://mcp.supabase.com'
[other]
url = "https://mcp.sentry.dev"
`,
	}
	for p, v := range configs {
		p = filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"mcp.context7.com", "mcp.exa.ai", "mcp.figma.com", "mcp.linear.app"}
	if got := Discover(home); !slices.Equal(got, want) {
		t.Fatal(got)
	}
}
func TestRejectURL(t *testing.T) {
	for _, u := range []string{"http://mcp.linear.app", "https://a.mcp.linear.app", "https://mcp.linear.app:8443", "https://x@mcp.linear.app", "https://8.8.8.8", "https://mcp.linear.app.", "https://mcp.linear.app.example", "https://localhost", "https://mcp.linear.app:"} {
		if candidate(u) != "" {
			t.Error(u)
		}
	}
}

func TestDiscoveryConfinesReadsAndLimitsEntries(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "config.toml"), []byte("[mcp_servers.a]\nurl='https://mcp.exa.ai'"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".codex")); err != nil {
		t.Skip("cannot create symlink")
	}
	if got := Discover(home); len(got) != 0 {
		t.Fatal("symlink escaped home", got)
	}
	cfg := []byte(`{"mcpServers":{`)
	for i := range 257 {
		if i > 0 {
			cfg = append(cfg, ',')
		}
		cfg = fmt.Appendf(cfg, `"s%d":{"url":"https://mcp.notion.com"}`, i)
	}
	cfg = append(cfg, "}}"...)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), cfg, 0600); err != nil {
		t.Fatal(err)
	}
	if got := Discover(home); len(got) != 0 {
		t.Fatal("unbounded server set", got)
	}
}

func TestAntigravityLegacyAndCurrent(t *testing.T) {
	home := t.TempDir()
	for i, p := range []string{".gemini/antigravity/mcp_config.json", ".gemini/config/mcp_config.json"} {
		p = filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		data := fmt.Sprintf(`{"mcpServers":{"good":{"serverUrl":"https://%s/mcp"},"disabled":{"serverUrl":"https://mcp.exa.ai","disabled":true}}}`, []string{"mcp.figma.com", "mcp.linear.app"}[i])
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := Discover(home); !slices.Equal(got, []string{"mcp.figma.com", "mcp.linear.app"}) {
		t.Fatal(got)
	}
}
