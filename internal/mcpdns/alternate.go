package mcpdns

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

var dnsClient = &http.Client{
	Timeout:       4 * time.Second,
	Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}
var invalidDNS = errors.New("unusable public DNS answer")

// Query a fixed IP over authenticated HTTPS. Neither proxy environment variables
// nor the system DNS resolver participate in the alternate lookup.
func alternateLookup(ctx context.Context, h string) ([]netip.Addr, error) {
	if catalog[h] == "" {
		return nil, invalidDNS
	}
	var out []netip.Addr
	for _, q := range []struct {
		name string
		code int
	}{{"A", 1}, {"AAAA", 28}} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?name="+h+"&type="+q.name, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := dnsClient.Do(req)
		if err != nil {
			return nil, err
		}
		const limit = 16 << 10
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		if err != nil || len(data) > limit || resp.StatusCode != http.StatusOK {
			return nil, invalidDNS
		}
		ips, err := parseAnswer(data, h, q.code)
		if err != nil {
			return nil, err
		}
		out = append(out, ips...)
	}
	return out, nil
}

func parseAnswer(data []byte, h string, kind int) ([]netip.Addr, error) {
	type record struct {
		Name string
		Type int
		Data string
	}
	var d struct {
		Status           *int
		TC               bool
		Question, Answer []record
	}
	if json.Unmarshal(data, &d) != nil || d.Status == nil || *d.Status != 0 || d.TC || len(d.Question) != 1 || d.Question[0].Type != kind || len(d.Answer) > 32 {
		return nil, invalidDNS
	}
	canonical := func(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
	if canonical(d.Question[0].Name) != h {
		return nil, invalidDNS
	}
	aliases := map[string]string{}
	for _, r := range d.Answer {
		if r.Type == 5 {
			name, target := canonical(r.Name), canonical(r.Data)
			if name == "" || target == "" || aliases[name] != "" {
				return nil, invalidDNS
			}
			aliases[name] = target
		}
	}
	owner := h
	for i := 0; aliases[owner] != ""; i++ {
		if i >= len(aliases) {
			return nil, invalidDNS
		}
		owner = aliases[owner]
	}
	var ips []netip.Addr
	for _, r := range d.Answer {
		if r.Type == 5 {
			continue
		}
		if r.Type != kind || canonical(r.Name) != owner {
			return nil, invalidDNS
		}
		ip, err := netip.ParseAddr(r.Data)
		if err != nil || !public(ip) || ip.Is4() != (kind == 1) || ip.Is4In6() {
			return nil, invalidDNS
		}
		ips = append(ips, ip)
	}
	return ips, nil
}
