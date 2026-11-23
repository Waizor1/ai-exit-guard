package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestActivityCorrelatesActualTunnelAndSeparatesWorker(t *testing.T) {
	ps := processTable("  10  1 /Applications/T3 Code.app/Contents/MacOS/T3 Code\n11 10 codex\n12 1 /Applications/Browser.app/Contents/MacOS/Browser")
	peers := map[string]string{"127.0.0.1:51000": "api.openai.com"}
	raw := "p10\nn127.0.0.1:51000->127.0.0.1:39178\np11\nn198.18.0.1:51012->198.18.1.1:443\nn198.18.0.1:51013->198.18.1.1:443\nn127.0.0.1:62000->127.0.0.1:7801\np12\nn127.0.0.1:51005->127.0.0.1:39178"
	rows := attribute(raw, ps, peers, map[netip.Addr][]string{netip.MustParseAddr("198.18.1.1"): {"chatgpt.com", "claude.ai"}})
	if len(rows) != 3 {
		t.Fatal(rows)
	}
	want := []activityRow{{"Browser", "", "listener", 1}, {"T3 Code", "api.openai.com", "guard", 1}, {"T3 Code · codex", "chatgpt.com, claude.ai", "outside", 2}}
	for i := range rows {
		if rows[i] != want[i] {
			t.Fatal(rows)
		}
	}
}

func TestActivitySocketTracksOnlyOpenAITunnels(t *testing.T) {
	// macOS Unix sockets have a short path limit.
	dir, err := os.MkdirTemp("/tmp", "aeg-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s")

	flows := &liveFlows{peers: map[string]string{}}
	l, e := flows.publish(path)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	closeFlow := flows.track("127.0.0.1:5555", "claude.ai")
	ignored := flows.track("127.0.0.1:5556", "ip123.in")
	defer ignored()
	m := readFlows(path)
	if len(m) != 1 || m["127.0.0.1:5555"] != "claude.ai" {
		t.Fatal(m)
	}
	closeFlow()
	if m := readFlows(path); m == nil || len(m) != 0 {
		t.Fatal(m)
	}
}
