package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Both platform engines use first-match rules. The relay makes the final
// destination and lease decision and never falls back to a direct dial.
func writeSystemProfile(w io.Writer, platform string) error {
	if platform != "windows" && platform != "darwin" {
		return fmt.Errorf("unsupported platform")
	}
	type fields = map[string]any
	windows := platform == "windows"
	var rules []fields
	add := func(name, process, proto, hosts, ports, action string) {
		if windows {
			ips, domains := "*", hosts
			if hosts == "127.0.0.1" {
				ips, domains = hosts, "*"
			}
			rules = append(rules, fields{"Name": name, "ProcessName": process, "Protocol": proto, "TargetHosts": ips, "TargetDomains": domains, "TargetPorts": ports, "Action": action, "ProxyConfigId": 1, "IsEnabled": true, "LocalhostViaProxy": process != "*"})
		} else {
			if action == "PROXY" {
				action = "guard"
			}
			rules = append(rules, fields{"localId": fmt.Sprintf("guard-%d", len(rules)+1), "name": name, "enabled": true, "processNames": process, "protocol": proto, "targetHosts": hosts, "targetPorts": ports, "action": action})
		}
	}
	clients := []string{"claude", "codex", "antigravity", "language_server_macos_arm", "language_server_macos_x64"}
	if windows {
		clients = []string{"claude.exe", "codex.exe", "antigravity.exe", "language_server_windows_x64.exe", "language_server_windows_arm64.exe"}
	}
	for _, client := range clients {
		add("Local Guard", client, "TCP", "127.0.0.1", "39178", "DIRECT")
		add("Protected client", client, "TCP", "*", "443", "PROXY")
		add("Block other TCP", client, "TCP", "*", "*", "BLOCK")
		add("Block UDP", client, "UDP", "*", "*", "BLOCK")
	}
	for _, domain := range aiDomains {
		// Use separate rules: adapters limit the size of each match field.
		for _, name := range []string{domain, "*." + domain} {
			add("AI HTTPS", "*", "TCP", name, "443", "PROXY")
			add("AI other TCP", "*", "TCP", name, "*", "BLOCK")
			// The macOS engine cannot match a UDP destination. A catch-all
			// UDP rule here would break unrelated apps.
			if windows {
				add("AI UDP", "*", "UDP", name, "*", "BLOCK")
			}
		}
	}
	var profile fields
	if windows {
		profile = fields{"Name": "AI Exit Guard", "ProxyConfigs": []fields{{"Id": 1, "Name": "Guard", "Host": "127.0.0.1", "Port": "39178", "Type": "HTTP", "SendDomainToProxy": true}}, "ProxyRules": rules}
	} else {
		profile = fields{"name": "AI Exit Guard", "dnsEnabled": true, "defaultProxyId": "guard", "proxyConfigs": []fields{{"id": "guard", "name": "Guard", "host": "127.0.0.1", "port": 39178, "type": "http", "sendDomain": true}}, "proxyRules": rules}
	}
	return json.NewEncoder(w).Encode(profile)
}

func isProtectedCountry(service, code string, countries map[string]string) bool {
	return len(code) == 2 && code != "UA" && strings.Contains(" "+countries[service]+" ", " "+code+" ")
}
