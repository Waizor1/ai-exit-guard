package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"time"

	"local/aiexitguard/internal/mcpdns"
)

// While a lease is in force the system resolver sees our answer. Expire the
// lease before measuring the original route again, even when the CDN is healthy.
type mcpLease struct {
	addrs    []netip.Addr
	until    time.Time
	verified time.Time
}

func recheckMCPLease(ctx context.Context, host string, l mcpLease) []netip.Addr {
	var live []netip.Addr
	for _, ip := range l.addrs {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		d := tls.Dialer{Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
		c, err := d.DialContext(attempt, "tcp", netip.AddrPortFrom(ip, 443).String())
		cancel()
		if err == nil {
			c.Close()
			live = append(live, ip)
		}
	}
	return live
}
func runMCPDNS(ctx context.Context) int {
	if os.Geteuid() == 0 {
		return 1
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return 1
	}
	p, e := net.FilePacketConn(os.Stdin)
	if e != nil {
		return 1
	}
	defer p.Close()
	l, e := net.FileListener(os.Stdout)
	if e != nil {
		return 1
	}
	defer l.Close()
	udp, ok := p.(*net.UDPConn)
	if !ok {
		return 1
	}
	tcp, ok := l.(*net.TCPListener)
	if !ok {
		return 1
	}
	if p.LocalAddr().String() != l.Addr().String() {
		return 1
	}
	addr, e := netip.ParseAddrPort(l.Addr().String())
	if e != nil || addr.Addr() != netip.MustParseAddr("127.0.0.1") || addr.Port() < 1024 {
		return 1
	}
	parent := os.Getppid()
	if parent < 2 {
		return 1
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if os.Getppid() != parent {
					stop()
					return
				}
			}
		}
	}()
	var answers mcpAnswers
	go answers.serve(ctx, udp, tcp)
	tracker := mcpdns.NewTrackerWithSystemLookup(nativeMCPLookup)
	leases := map[string]mcpLease{}
	var previous [32]byte
	encoder := json.NewEncoder(os.Stderr)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-timer.C:
		}
		start := time.Now()
		candidates := mcpdns.Discover(home)
		records := map[string][]netip.Addr{}
		names := []string{}
		cycle, cancel := context.WithTimeout(ctx, 18*time.Second)
		// Absence of configured catalog hosts is the normal idle case.
		var network *mcpNetwork
		if len(candidates) > 0 {
			network, _ = mcpSystemNetwork(cycle, addr.Port())
		}
		if network == nil || network.signature != previous {
			tracker = mcpdns.NewTrackerWithSystemLookup(nativeMCPLookup)
			clear(leases)
			answers.replace(nil, originalDNS{}, time.Time{})
		}
		if network != nil {
			previous = network.signature
			var probes []string
			for host := range leases {
				if !slices.Contains(candidates, host) || network.excludes(host) {
					delete(leases, host)
				}
			}
			for _, host := range candidates {
				if network.excludes(host) {
					continue
				}
				if lease, found := leases[host]; found {
					if !start.Before(lease.until) {
						delete(leases, host)
						continue
					}
					if start.Sub(lease.verified) >= 45*time.Second {
						verified := recheckMCPLease(cycle, host, lease)
						if len(verified) == 0 {
							delete(leases, host)
							continue
						}
						lease.addrs, lease.verified = verified, time.Now()
						leases[host] = lease
					}
				} else {
					probes = append(probes, host)
				}
			}
			// Recheck split-DNS at the boundary immediately before disclosing a public hostname.
			exclude := func(host string) bool {
				current, err := mcpSystemNetwork(cycle, addr.Port())
				return err != nil || current.signature != previous || current.excludes(host)
			}
			verified := tracker.Verified(cycle, probes, exclude)
			for host, ips := range verified {
				if len(leases) < 10 {
					leases[host] = mcpLease{ips, start.Add(3 * time.Minute), start}
				}
			}
			deadline := start.Add(55 * time.Second)
			// Take a new snapshot even if the probe deadline was reached. Never publish a result from a former network.
			verifyCtx, done := context.WithTimeout(ctx, 2*time.Second)
			current, err := mcpSystemNetwork(verifyCtx, addr.Port())
			done()
			if err == nil && current.signature == previous {
				configured := mcpdns.Discover(home)
				for host, lease := range leases {
					if !current.excludes(host) && slices.Contains(configured, host) && time.Now().Before(lease.until) {
						records[host] = lease.addrs
						names = append(names, host)
						if lease.until.Before(deadline) {
							deadline = lease.until
						}
					} else {
						delete(leases, host)
					}
				}
				answers.replace(records, current.original, deadline)
			} else {
				clear(leases)
				answers.replace(nil, originalDNS{}, time.Time{})
			}
		}
		cancel()
		sort.Strings(names)
		if encoder.Encode(names) != nil {
			return 1
		}
		next := 3 * time.Minute
		if len(leases) > 0 || tracker.NeedsConfirmation() {
			next = 25 * time.Second
		}
		timer.Reset(next)
	}
}
