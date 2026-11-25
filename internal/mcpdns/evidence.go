package mcpdns

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"
)

// IsGlobalUnicast includes shared, reserved, benchmarking and transition networks.
var special = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}
var globalV6 = netip.MustParsePrefix("2000::/3")

func public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || (ip.Is6() && !globalV6.Contains(ip)) {
		return false
	}
	for _, p := range special {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
func publicSet(ips []netip.Addr) bool {
	if len(ips) == 0 || len(ips) > 16 {
		return false
	}
	for _, ip := range ips {
		if !public(ip) {
			return false
		}
	}
	return true
}

type lookup func(context.Context, string) ([]netip.Addr, error)
type handshake func(context.Context, string, netip.Addr) error

func probeTLS(ctx context.Context, h string, ip netip.Addr) error {
	d := tls.Dialer{Config: &tls.Config{ServerName: h, MinVersion: tls.VersionTLS12}}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, 443).String())
	if err == nil {
		c.Close()
	}
	return err
}

// Only transport failures count. Certificate, protocol and other security errors fail closed.
func transportFailure(err error) bool {
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return false
	}
	var timeout net.Error
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || (errors.As(err, &timeout) && timeout.Timeout())
}

// ErrNoDNSAnswer is reserved for a native resolver's explicit no-name or temporary DNS
// failure. An empty success, subprocess failure, timeout of our own cycle, or malformed
// output cannot substitute for that evidence.
var ErrNoDNSAnswer = errors.New("native DNS has no answer")

func nativeFailure(ctx context.Context, h string, system lookup, probe handshake) ([]netip.Addr, bool) {
	normal, err := system(ctx, h)
	if ctx.Err() != nil {
		return nil, false
	}
	if len(normal) == 0 && errors.Is(err, ErrNoDNSAnswer) {
		return nil, true
	}
	if err != nil || !publicSet(normal) {
		return nil, false
	}
	for _, ip := range normal {
		if ctx.Err() != nil || !transportFailure(probe(ctx, h, ip)) {
			return nil, false
		}
	}
	return normal, ctx.Err() == nil
}

func verifiedAlternates(ctx context.Context, h string, normal []netip.Addr, alternate lookup, probe handshake) []netip.Addr {
	other, err := alternate(ctx, h)
	if err != nil || !publicSet(other) {
		return nil
	}
	var verified []netip.Addr
	for _, ip := range other {
		if slices.ContainsFunc(normal, func(n netip.Addr) bool { return n.Unmap() == ip.Unmap() }) || slices.Contains(verified, ip.Unmap()) {
			continue
		}
		if ctx.Err() == nil && probe(ctx, h, ip) == nil {
			verified = append(verified, ip.Unmap())
		}
	}
	return verified
}

// Tracker retains evidence for the immediately preceding scan only.
type Tracker struct {
	mu       sync.Mutex
	previous map[string]bool
	system   lookup
	after    string
	repeat   bool
	pending  bool
}

// NewTrackerWithSystemLookup uses the caller's native absolute system resolver.
func NewTrackerWithSystemLookup(system func(context.Context, string) ([]netip.Addr, error)) *Tracker {
	return &Tracker{system: system}
}

// Verified returns only public alternate addresses that completed certificate-verified TLS
// for configured catalog hosts in a second consecutive qualifying scan. A nil policy or
// system resolver fails closed. excluded must check hosts and active scoped DNS policy.
func (t *Tracker) Verified(ctx context.Context, candidates []string, excluded func(string) bool) map[string][]netip.Addr {
	return t.scan(ctx, candidates, excluded, t.system, alternateLookup, probeTLS)
}

// NeedsConfirmation reports a newly observed qualifying native failure in the
// last completed scan. Reading it performs no probes.
func (t *Tracker) NeedsConfirmation() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pending
}

// Pair scans of each batch so a fully configured client can collect evidence on
// consecutive cycles. Resume after the last hostname even if the config changes.
func (t *Tracker) batch(candidates []string) []string {
	const limit = 10
	hosts := make([]string, 0, len(candidates))
	for _, h := range candidates {
		if catalog[h] != "" {
			hosts = append(hosts, h)
		}
	}
	slices.Sort(hosts)
	hosts = slices.Compact(hosts)
	if len(hosts) <= limit {
		t.after = ""
		t.repeat = false
		return hosts
	}
	start, _ := slices.BinarySearch(hosts, t.after)
	if start < len(hosts) && hosts[start] == t.after {
		start++
	}
	batch := make([]string, limit)
	for i := range batch {
		batch[i] = hosts[(start+i)%len(hosts)]
	}
	if t.repeat {
		t.after = batch[len(batch)-1]
	}
	t.repeat = !t.repeat
	return batch
}

func (t *Tracker) scan(ctx context.Context, candidates []string, excluded func(string) bool, system, alternate lookup, probe handshake) map[string][]netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	next := make(map[string]bool)
	t.pending = false
	verified := make(map[string][]netip.Addr)
	if excluded != nil && system != nil {
		for _, h := range t.batch(candidates) {
			if ctx.Err() != nil {
				break
			}
			if excluded(h) {
				continue
			}
			normal, failed := nativeFailure(ctx, h, system, probe)
			if !failed || excluded(h) {
				continue
			}
			if !t.previous[h] {
				t.pending = true
				next[h] = true
				continue
			}
			ips := verifiedAlternates(ctx, h, normal, alternate, probe)
			if len(ips) > 0 && !excluded(h) {
				next[h] = true
				verified[h] = ips
			}
		}
	}
	if ctx.Err() != nil {
		next = nil
		t.pending = false
		verified = nil
	}
	t.previous = next
	return verified
}
