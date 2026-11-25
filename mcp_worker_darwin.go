package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	state := mcpWorkerState{home: home, port: addr.Port(), leases: make(map[string]mcpLease), answers: &answers, encoder: json.NewEncoder(os.Stderr)}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-timer.C:
		}
		next, err := state.scan(ctx)
		if err != nil {
			return 1
		}
		timer.Reset(next)
	}
}

const mcpHardLease = 3 * time.Minute
const mcpFastRetry = 5 * time.Second

type mcpWorkerState struct {
	home    string
	port    uint16
	leases  map[string]mcpLease
	network *mcpNetwork
	tracker *mcpdns.Tracker
	answers *mcpAnswers
	encoder *json.Encoder
	sent    []string
}

// When our temporary resolver is active, the ordinary getaddrinfo result for
// that host is our own reply. Recheck its previous system DNS and TLS path
// directly before a hard lease expires. Only a fresh differential test extends it.
func (s *mcpWorkerState) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if _, active := s.leases[host]; !active {
		return nativeMCPLookup(ctx, host)
	}
	endpoints := s.network.original.endpoints()
	var last error
	for _, endpoint := range endpoints {
		attempt, end := context.WithTimeout(ctx, 1500*time.Millisecond)
		resolver := net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return endpoint.dial(ctx, network)
		}}
		ips, err := resolver.LookupNetIP(attempt, "ip", host+".")
		end()
		if len(ips) > 0 || err == nil {
			return ips, err
		}
		var failure *net.DNSError
		if errors.As(err, &failure) && failure.IsNotFound {
			return nil, mcpdns.ErrNoDNSAnswer
		}
		last = err
	}
	return nil, last
}

func (s *mcpWorkerState) publish(now time.Time, heartbeat bool) error {
	records := map[string][]netip.Addr{}
	names := []string{}
	expires := now.Add(60 * time.Second)
	for host, lease := range s.leases {
		if !now.Before(lease.until) {
			continue
		}
		records[host] = lease.addrs
		names = append(names, host)
		if lease.until.Before(expires) {
			expires = lease.until
		}
	}
	sort.Strings(names)
	var original originalDNS
	if s.network != nil {
		original = s.network.original
	}
	var check func(context.Context, string) bool
	if s.network != nil && len(records) > 0 {
		signature, port := s.network.signature, s.port
		check = func(ctx context.Context, host string) bool {
			bounded, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			current, err := mcpSystemNetwork(bounded, port)
			return err == nil && current.signature == signature && !current.excludes(host)
		}
	}
	s.answers.replaceChecked(records, original, expires, check)
	if heartbeat || !slices.Equal(names, s.sent) {
		if err := s.encoder.Encode(names); err != nil {
			return err
		}
		s.sent = names
	}
	return nil
}

func (s *mcpWorkerState) prune(candidates []string, now time.Time) bool {
	removed := false
	for host, lease := range s.leases {
		if !now.Before(lease.until) || s.network == nil || s.network.excludes(host) || !slices.Contains(candidates, host) {
			delete(s.leases, host)
			removed = true
		}
	}
	return removed
}

func (s *mcpWorkerState) adopt(n *mcpNetwork) {
	if s.network == nil || n == nil || s.network.signature != n.signature {
		s.tracker = mcpdns.NewTrackerWithSystemLookup(s.lookup)
		clear(s.leases)
	}
	s.network = n
}

func (s *mcpWorkerState) nextDelay(now time.Time, removed bool) time.Duration {
	if removed {
		return mcpFastRetry
	}
	delay := 3 * time.Minute
	if len(s.leases) > 0 || s.tracker.NeedsConfirmation() {
		delay = 25 * time.Second
	}
	for _, l := range s.leases {
		if remaining := l.until.Sub(now); remaining < delay {
			delay = max(remaining, time.Millisecond)
		}
	}
	return delay
}

func (s *mcpWorkerState) scan(parent context.Context) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, 18*time.Second)
	defer cancel()
	now := time.Now()
	candidates := mcpdns.Discover(s.home)
	var n *mcpNetwork
	if len(candidates) > 0 {
		n, _ = mcpSystemNetwork(ctx, s.port)
	}
	s.adopt(n)
	removed := s.prune(candidates, now)
	// Withdraw invalid/expired domains before any network checks can block.
	if err := s.publish(now, false); err != nil {
		return 0, err
	}
	if n == nil {
		return s.nextDelay(now, removed), s.publish(now, true)
	}

	var probes []string
	for _, h := range candidates {
		if n.excludes(h) {
			continue
		}
		l, active := s.leases[h]
		if active && now.Sub(l.verified) >= 45*time.Second {
			// One slow host cannot consume the probe budget for the entire scan.
			verify, done := context.WithTimeout(ctx, 2300*time.Millisecond)
			live := recheckMCPLease(verify, h, l)
			done()
			if len(live) == 0 {
				if ctx.Err() == nil {
					delete(s.leases, h)
					removed = true
				}
				continue
			}
			l.addrs, l.verified = live, time.Now()
			s.leases[h] = l
		}
		if !active || l.until.Sub(now) <= 2*time.Minute {
			probes = append(probes, h)
		}
	}
	// The tracker may check hosts concurrently. The network and lease maps are
	// read-only until Verified returns.
	exclude := func(host string) bool {
		live, err := mcpSystemNetwork(ctx, s.port)
		return err != nil || live.signature != n.signature || live.excludes(host)
	}
	verified := s.tracker.Verified(ctx, probes, exclude)
	finish, done := context.WithTimeout(parent, 2*time.Second)
	current, err := mcpSystemNetwork(finish, s.port)
	done()
	if err != nil || current.signature != n.signature {
		s.adopt(nil)
		return mcpFastRetry, s.publish(time.Now(), true)
	}
	s.network = current
	configured := mcpdns.Discover(s.home)
	now = time.Now()
	removed = s.prune(configured, now) || removed
	for h, ips := range verified {
		_, existing := s.leases[h]
		if (existing || len(s.leases) < 10) && slices.Contains(configured, h) && !current.excludes(h) {
			s.leases[h] = mcpLease{ips, now.Add(mcpHardLease), now}
		}
	}
	return s.nextDelay(now, removed), s.publish(now, true)
}
