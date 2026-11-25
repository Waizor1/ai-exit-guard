package main

import (
	"net/netip"
	"testing"
)

const regularMCPResolver = "DNS configuration\n\nresolver #1\n  nameserver[0] : 10.10.20.1\n  if_index : 5 (utun4)\n  flags : Request A records\n"
const localMCPResolver = "\nresolver #2\n  domain : mcp.linear.app\n  nameserver[0] : 127.0.0.1\n  port : 51000\n  flags : Supplemental\n"
const splitMCPResolver = "\nresolver #3\n  domain : corp.example\n  search domain[0] : internal.example\n  nameserver[0] : 10.10.20.5\n"
const scopedMCPResolver = "\nDNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n  if_index : 4 (en0)\n  flags : Scoped\n"
const plainMCPProxy = "<dictionary> {\n  FTPPassive : 1\n}\n"

func TestMCPNetworkScope(t *testing.T) {
	const hosts = "127.0.0.1 localhost\n192.168.2.1 mcp.private.example # override\n"
	config := regularMCPResolver + splitMCPResolver + scopedMCPResolver
	n, e := parseMCPNetwork(config, hosts, plainMCPProxy, 51000)
	if e != nil || n.original.server != netip.MustParseAddrPort("10.10.20.1:53") || n.original.iface != 5 {
		t.Fatalf("unexpected resolver %v %v", n, e)
	}
	for _, h := range []string{"x.corp.example", "internal.example", "mcp.private.example", "api.openai.com", "ip123.in", "api.anthropic.com", "antigravity.google"} {
		if !n.excludes(h) {
			t.Errorf("accepted excluded %s", h)
		}
	}
	if n.excludes("mcp.linear.app") {
		t.Fatal("excluded independent public host")
	}
	ours, e := parseMCPNetwork(regularMCPResolver+localMCPResolver+splitMCPResolver+scopedMCPResolver, hosts, plainMCPProxy, 51000)
	if e != nil || ours.signature != n.signature || ours.excludes("mcp.linear.app") {
		t.Fatal("scoped lease masked original signature", e)
	}
	foreign, e := parseMCPNetwork(regularMCPResolver+localMCPResolver+splitMCPResolver+scopedMCPResolver, hosts, plainMCPProxy, 51001)
	if e != nil || foreign.signature == n.signature || !foreign.excludes("mcp.linear.app") {
		t.Fatal("foreign resolver not respected", e)
	}
	if _, e := parseMCPNetwork(config, hosts, "<dictionary> {\nHTTPEnable : 1\n}", 51000); e == nil {
		t.Fatal("overrode system proxy")
	}
	if _, e := parseMCPNetwork(regularMCPResolver+"\nresolver #2\n  nameserver[0] : 1.1.1.1\n", hosts, plainMCPProxy, 51000); e == nil {
		t.Fatal("ambiguous resolver selected")
	}
}
