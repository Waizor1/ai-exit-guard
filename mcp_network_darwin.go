// The macOS DNS worker only runs while the menu owns its loopback sockets.
package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"local/aiexitguard/internal/mcpdns"
)

type originalDNS struct {
	server netip.AddrPort
	iface  int
}
type mcpNetwork struct {
	original  originalDNS
	domains   []string
	hosts     map[string]bool
	signature [32]byte
}

func domainRelated(a, b string) bool {
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// Exclude the worker's own resolver from the snapshot. Preserve every other
// resolver in the signature so a VPN or split-DNS change invalidates evidence.
func parseMCPNetwork(raw, hosts, proxy string, localPort uint16) (*mcpNetwork, error) {
	s := &mcpNetwork{hosts: map[string]bool{}}
	if !strings.HasPrefix(raw, "DNS configuration\n") || !strings.HasPrefix(strings.TrimSpace(proxy), "<dictionary> {") {
		return nil, fmt.Errorf("missing system configuration")
	}
	for line := range strings.SplitSeq(proxy, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && strings.HasSuffix(fields[0], "Enable") && fields[2] == "1" {
			return nil, fmt.Errorf("explicit system proxy")
		}
	}
	for line := range strings.SplitSeq(hosts, "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(f) > 1 {
			for _, h := range f[1:] {
				s.hosts[strings.ToLower(strings.TrimSuffix(h, "."))] = true
			}
		}
	}
	chunks := strings.Split(raw, "\nresolver #")
	var signature strings.Builder
	scoped := false
	for _, chunk := range chunks[1:] {
		data, tail, hasTail := strings.Cut(chunk, "\nDNS configuration (")
		f := strings.SplitN(data, "\n", 2)
		if len(f) < 2 {
			return nil, fmt.Errorf("invalid resolver")
		}
		body := strings.TrimSpace(f[1])
		var ip []netip.Addr
		var domains []string
		port, iface := 53, 0
		var suffix string
		var unusual bool
		for ln := range strings.SplitSeq(body, "\n") {
			k, v, ok := strings.Cut(ln, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch {
			case k == "domain":
				suffix = strings.ToLower(strings.TrimSuffix(v, "."))
				domains = append(domains, suffix)
			case strings.HasPrefix(k, "search domain["):
				domains = append(domains, strings.ToLower(strings.TrimSuffix(v, ".")))
			case strings.HasPrefix(k, "nameserver["):
				a, e := netip.ParseAddr(v)
				if e != nil {
					return nil, e
				}
				ip = append(ip, a)
			case k == "port":
				p, e := strconv.Atoi(v)
				if e != nil || p < 1 || p > 65535 {
					return nil, fmt.Errorf("invalid port")
				}
				port = p
			case k == "if_index":
				parts := strings.Fields(v)
				if len(parts) == 0 {
					return nil, fmt.Errorf("absent interface")
				}
				n, e := strconv.Atoi(parts[0])
				if e != nil || n < 1 {
					return nil, fmt.Errorf("invalid interface")
				}
				iface = n
			case k == "options":
				unusual = true
			}
		}
		own := suffix != "" && port == int(localPort) && len(ip) == 1 && ip[0].String() == "127.0.0.1"
		if !own {
			signature.WriteString(body + "\n")
			s.domains = append(s.domains, domains...)
			if !scoped && suffix == "" {
				if unusual || len(ip) != 1 {
					return nil, fmt.Errorf("ambiguous default DNS")
				}
				original := originalDNS{netip.AddrPortFrom(ip[0], uint16(port)), iface}
				if s.original.server.IsValid() && s.original != original {
					return nil, fmt.Errorf("multiple default routes")
				}
				s.original = original
			}
		}
		if hasTail {
			scoped = true
			signature.WriteString(tail)
		}
	}
	if !s.original.server.IsValid() {
		return nil, fmt.Errorf("no default DNS")
	}
	s.signature = sha256.Sum256([]byte(signature.String() + hosts + proxy))
	return s, nil
}
func mcpSystemNetwork(ctx context.Context, port uint16) (*mcpNetwork, error) {
	dns, e := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	if e != nil {
		return nil, e
	}
	p, e := exec.CommandContext(ctx, "/usr/sbin/scutil", "--proxy").Output()
	if e != nil {
		return nil, e
	}
	h, e := os.ReadFile("/etc/hosts")
	if e != nil || len(h) > 4<<20 {
		return nil, fmt.Errorf("hosts unavailable")
	}
	n, e := parseMCPNetwork(string(dns), string(h), string(p), port)
	if e != nil {
		return nil, e
	}
	if n.original.iface == 0 {
		args := []string{"-n", "get"}
		if n.original.server.Addr().Is6() {
			args = append(args, "-inet6")
		}
		info, err := exec.CommandContext(ctx, "/sbin/route", append(args, n.original.server.Addr().String())...).Output()
		if err != nil {
			return nil, err
		}
		for line := range strings.SplitSeq(string(info), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok && strings.TrimSpace(k) == "interface" {
				iface, err := net.InterfaceByName(strings.TrimSpace(v))
				if err != nil {
					return nil, err
				}
				n.original.iface = iface.Index
				break
			}
		}
		if n.original.iface <= 0 {
			return nil, fmt.Errorf("unknown resolver interface")
		}
		n.signature = sha256.Sum256([]byte(fmt.Sprintf("%x/%d", n.signature, n.original.iface)))
	}
	dirs, e := os.ReadDir("/etc/resolver")
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	for _, d := range dirs {
		n.domains = append(n.domains, strings.ToLower(d.Name()))
	}
	return n, nil
}
func (n *mcpNetwork) excludes(h string) bool {
	if aiHost(h) || n.hosts[h] {
		return true
	}
	for _, s := range n.domains {
		if s == "" || domainRelated(h, s) {
			return true
		}
	}
	for _, s := range []string{"ip123.in", "ipinfo.io", "www.cloudflare.com"} {
		if domainRelated(h, s) {
			return true
		}
	}
	return false
}

// The worker sets netdns=cgo. Go on Darwin calls libSystem getaddrinfo even
// in our CGO_ENABLED=0 build (net/cgo_unix_syscall.go).
func nativeMCPLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host+".")
	var failure *net.DNSError
	if ctx.Err() == nil && len(addresses) == 0 && errors.As(err, &failure) && (failure.IsNotFound || failure.IsTemporary) {
		return nil, mcpdns.ErrNoDNSAnswer
	}
	return addresses, err
}
func (o originalDNS) dial(ctx context.Context, network string) (net.Conn, error) {
	var d net.Dialer
	if o.iface != 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var set error
			err := c.Control(func(fd uintptr) {
				level, opt := syscall.IPPROTO_IP, syscall.IP_BOUND_IF
				if o.server.Addr().Is6() {
					level, opt = syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF
				}
				set = syscall.SetsockoptInt(int(fd), level, opt, o.iface)
			})
			if err != nil {
				return err
			}
			return set
		}
	}
	return d.DialContext(ctx, network, o.server.String())
}
