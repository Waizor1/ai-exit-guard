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
			rules = append(rules, fields{"Name": name, "ProcessName": process, "Protocol": proto, "TargetHosts": "*", "TargetDomains": hosts, "TargetPorts": ports, "Action": action, "ProxyConfigId": 1, "IsEnabled": true, "LocalhostViaProxy": false})
		} else {
			if action == "PROXY" {
				action = "guard"
			}
			rules = append(rules, fields{"localId": fmt.Sprintf("guard-%d", len(rules)+1), "name": name, "enabled": true, "processNames": process, "protocol": proto, "targetHosts": hosts, "targetPorts": ports, "action": action})
		}
	}
	clients := []string{"Antigravity", "agy", "language_server_macos_arm", "language_server_macos_x64"}
	t3Hosts := []string{"T3 Code", "T3 Code (Beta)"}
	if windows {
		clients = []string{"antigravity.exe", "language_server_windows_x64.exe", "language_server_windows_arm64.exe"}
		t3Hosts = []string{"T3 Code.exe", "T3 Code (Beta).exe"}
	}
	for _, client := range clients {
		for _, host := range explicitGoogleHosts {
			add("Antigravity HTTPS", client, "TCP", host, "443", "PROXY")
		}
	}
	// T3 itself refreshes the Google token and reads the account identity.
	// These shared endpoints must not become system-wide Google proxy rules.
	for _, app := range t3Hosts {
		for _, host := range []string{"oauth2.googleapis.com", "www.googleapis.com"} {
			add("Antigravity account", app, "TCP", host, "443", "PROXY")
		}
	}
	add("Gemini API", "*", "TCP", geminiAPI, "443", "PROXY")
	for _, domain := range aiDomains {
		// Use separate rules: adapters limit the size of each match field.
		for _, name := range []string{domain, "*." + domain} {
			add("AI HTTPS", "*", "TCP", name, "443", "PROXY")
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
