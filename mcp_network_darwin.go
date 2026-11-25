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
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"local/aiexitguard/internal/mcpdns"
)

type originalDNS struct {
	server    netip.AddrPort
	iface     int
	secondary []originalDNS
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

// scutil prints nested dictionaries and arrays. A proxy enable flag and its
// endpoint and scope must all belong to the very same dictionary.
type proxyBlock struct {
	kind     string
	fields   map[string]string
	children map[string]*proxyBlock
}

func guardProxySnapshot(raw string) bool {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if lines[0] != "<dictionary> {" {
		return false
	}
	root := &proxyBlock{kind: "<dictionary>", fields: map[string]string{}, children: map[string]*proxyBlock{}}
	stack := []*proxyBlock{root}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if len(stack) == 0 {
			return false
		}
		if line == "}" {
			stack = stack[:len(stack)-1]
			continue
		}
		key, val, ok := strings.Cut(line, " : ")
		if !ok || key == "" || key != strings.TrimSpace(key) {
			return false
		}
		cur := stack[len(stack)-1]
		if _, ok := cur.fields[key]; ok || cur.children[key] != nil {
			return false
		}
		if cur.kind == "<array>" && key != strconv.Itoa(len(cur.fields)+len(cur.children)) {
			return false
		}
		if val == "<array> {" || val == "<dictionary> {" {
			if len(stack) > 32 {
				return false
			}
			child := &proxyBlock{kind: strings.TrimSuffix(val, " {"), fields: map[string]string{}, children: map[string]*proxyBlock{}}
			cur.children[key] = child
			stack = append(stack, child)
		} else {
			cur.fields[key] = val
		}
	}
	return len(stack) == 0 && root.safe()
}
func (p *proxyBlock) safe() bool {
	for k, c := range p.children {
		if strings.HasSuffix(k, "Enable") || !c.safe() {
			return false
		}
	}
	for k, v := range p.fields {
		if !strings.HasSuffix(k, "Enable") || v == "0" {
			continue
		}
		if v != "1" {
			return false
		}
		switch k {
		case "ProxyAutoConfigEnable":
			if p.fields["ProxyAutoConfigURLString"] != "http://127.0.0.1:39178/guard.pac" || p.fields["ProxyAutoConfigJavaScript"] != "" {
				return false
			}
		case "HTTPEnable", "HTTPSEnable":
			prefix := strings.TrimSuffix(k, "Enable")
			if p.fields[prefix+"Proxy"] != "127.0.0.1" || p.fields[prefix+"Port"] != "39178" {
				return false
			}
			if !p.guardDomains() {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (p *proxyBlock) guardDomains() bool {
	var names []string
	for _, key := range []string{"SupplementalMatchDomain", "__MATCH_DOMAIN__", "SupplementalMatchDomains"} {
		if name, ok := p.fields[key]; ok {
			if key == "SupplementalMatchDomains" {
				return false
			}
			names = append(names, name)
		}
		if array := p.children[key]; array != nil {
			if key != "SupplementalMatchDomains" || array.kind != "<array>" || len(array.children) != 0 || len(array.fields) == 0 {
				return false
			}
			for _, name := range array.fields {
				names = append(names, name)
			}
		}
	}
	for _, name := range names {
		if !aiHost(name) {
			return false
		}
		for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return false
				}
			}
		}
	}
	return len(names) > 0
}

func (o originalDNS) endpoints() []originalDNS {
	return append([]originalDNS{{server: o.server, iface: o.iface}}, o.secondary...)
}

// Exclude the worker's own resolver from the snapshot. Preserve every other
// resolver in the signature so a VPN or split-DNS change invalidates evidence.
func parseMCPNetwork(raw, hosts, proxy string, localPort uint16) (*mcpNetwork, error) {
	s := &mcpNetwork{hosts: map[string]bool{}}
	if !strings.HasPrefix(raw, "DNS configuration\n") || !strings.HasPrefix(strings.TrimSpace(proxy), "<dictionary> {") {
		return nil, fmt.Errorf("missing system configuration")
	}
	if !guardProxySnapshot(proxy) {
		return nil, fmt.Errorf("unrecognized system proxy")
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
	bestOrder := int64(1 << 62)
	ambiguous := false
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
		order := int64(200000)
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
			case k == "order":
				parsed, e := strconv.ParseUint(v, 10, 32)
				if e != nil {
					return nil, e
				}
				order = int64(parsed)
			case k == "options":
				unusual = true
			}
		}
		own := suffix != "" && port == int(localPort) && len(ip) == 1 && ip[0].String() == "127.0.0.1"
		if !own {
			signature.WriteString(body + "\n")
			s.domains = append(s.domains, domains...)
			if !scoped && suffix == "" && order <= bestOrder {
				var original originalDNS
				for i, addr := range ip {
					ep := originalDNS{server: netip.AddrPortFrom(addr, uint16(port)), iface: iface}
					if i == 0 {
						original = ep
					} else {
						original.secondary = append(original.secondary, ep)
					}
				}
				if order < bestOrder {
					bestOrder = order
					ambiguous = false
					s.original = original
				}
				ambiguous = ambiguous || unusual || len(ip) == 0 || !reflect.DeepEqual(original, s.original)
			}
		}
		if hasTail {
			scoped = true
			signature.WriteString(tail)
		}
	}
	if ambiguous || !s.original.server.IsValid() {
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
	endpoints := n.original.endpoints()
	for i := range endpoints {
		ep := &endpoints[i]
		if ep.iface == 0 {
			args := []string{"-n", "get"}
			if ep.server.Addr().Is6() {
				args = append(args, "-inet6")
			}
			info, err := exec.CommandContext(ctx, "/sbin/route", append(args, ep.server.Addr().String())...).Output()
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
					ep.iface = iface.Index
					break
				}
			}
			if ep.iface <= 0 {
				return nil, fmt.Errorf("unknown resolver interface")
			}
			n.signature = sha256.Sum256([]byte(fmt.Sprintf("%x/%d", n.signature, ep.iface)))
		}
	}
	n.original = endpoints[0]
	n.original.secondary = endpoints[1:]
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
