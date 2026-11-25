package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	systemDNSLimit       = 4096
	systemDNSProbePeriod = 25 * time.Second
	systemDNSQueryBudget = 5 * time.Second
	systemDNSCacheMax    = 2048
	systemDNSMinTTL      = 15 * time.Second
	systemDNSMaxTTL      = 5 * time.Minute
	systemDNSIdleConnMax = 25 * time.Second
)

type dotUpstream struct {
	addr       string
	serverName string
	label      string
}

var defaultDoTUpstreams = []dotUpstream{
	{addr: "8.8.8.8:853", serverName: "dns.google", label: "8.8.8.8"},
	{addr: "8.8.4.4:853", serverName: "dns.google", label: "8.8.4.4"},
	{addr: "9.9.9.9:853", serverName: "dns.quad9.net", label: "9.9.9.9"},
	{addr: "1.1.1.1:853", serverName: "cloudflare-dns.com", label: "1.1.1.1"},
}

type systemDNSStatus struct {
	Ready    bool   `json:"ready"`
	Upstream string `json:"upstream,omitempty"`
}

type pooledTLSConn struct {
	conn net.Conn
	used time.Time
}

type dotCacheKey struct {
	host string
	kind uint16
}

type dotCacheEntry struct {
	resp    []byte
	expires time.Time
}

type dotResolver struct {
	upstreams []dotUpstream
	tlsConfig func(dotUpstream) *tls.Config
	ranked    atomic.Pointer[[]dotUpstream]

	poolMu sync.Mutex
	pools  map[string][]pooledTLSConn

	cacheMu sync.Mutex
	cache   map[dotCacheKey]dotCacheEntry
}

func newDoTResolver(upstreams []dotUpstream) *dotResolver {
	if len(upstreams) == 0 {
		upstreams = defaultDoTUpstreams
	}
	r := &dotResolver{
		upstreams: slices.Clone(upstreams),
		pools:     make(map[string][]pooledTLSConn),
		cache:     make(map[dotCacheKey]dotCacheEntry),
	}
	r.tlsConfig = func(u dotUpstream) *tls.Config {
		return &tls.Config{ServerName: u.serverName, MinVersion: tls.VersionTLS12}
	}
	return r
}

func (r *dotResolver) getConn(addr string) net.Conn {
	r.poolMu.Lock()
	defer r.poolMu.Unlock()
	list := r.pools[addr]
	now := time.Now()
	for len(list) > 0 {
		last := list[len(list)-1]
		list = list[:len(list)-1]
		if now.Sub(last.used) <= systemDNSIdleConnMax {
			r.pools[addr] = list
			return last.conn
		}
		last.conn.Close()
	}
	r.pools[addr] = nil
	return nil
}

func (r *dotResolver) putConn(addr string, c net.Conn) {
	r.poolMu.Lock()
	defer r.poolMu.Unlock()
	list := r.pools[addr]
	if len(list) >= 4 {
		c.Close()
		return
	}
	r.pools[addr] = append(list, pooledTLSConn{conn: c, used: time.Now()})
}

func (r *dotResolver) closePools() {
	r.poolMu.Lock()
	defer r.poolMu.Unlock()
	for addr, list := range r.pools {
		for _, item := range list {
			item.conn.Close()
		}
		delete(r.pools, addr)
	}
}

func (r *dotResolver) dialDoT(ctx context.Context, u dotUpstream) (net.Conn, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 2500 * time.Millisecond},
		Config:    r.tlsConfig(u),
	}
	return d.DialContext(ctx, "tcp", u.addr)
}

func (r *dotResolver) exchangeUpstream(ctx context.Context, u dotUpstream, query []byte) ([]byte, error) {
	if c := r.getConn(u.addr); c != nil {
		resp, err := exchangeDoTConn(ctx, c, query)
		if err == nil {
			r.putConn(u.addr, c)
			return resp, nil
		}
		c.Close()
	}
	c, err := r.dialDoT(ctx, u)
	if err != nil {
		return nil, err
	}
	resp, err := exchangeDoTConn(ctx, c, query)
	if err != nil {
		c.Close()
		return nil, err
	}
	r.putConn(u.addr, c)
	return resp, nil
}

func exchangeDoTConn(ctx context.Context, c net.Conn, query []byte) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2500 * time.Millisecond)
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := writeMCPFrame(c, query); err != nil {
		return nil, err
	}
	resp, err := readMCPFrame(c)
	if err != nil {
		return nil, err
	}
	if len(resp) < 12 || resp[0] != query[0] || resp[1] != query[1] || resp[2]&0x80 == 0 {
		return nil, errors.New("invalid DoT response")
	}
	return resp, nil
}

// Probe query: standard IN A for "google.com" with txid 0x5152.
var dotProbePacket = []byte{
	0x51, 0x52, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
	0x00, 0x01, 0x00, 0x01,
}

func (r *dotResolver) probeAll(parent context.Context) (bool, string) {
	type probeResult struct {
		upstream dotUpstream
		latency  time.Duration
		ok       bool
	}
	results := make([]probeResult, len(r.upstreams))
	var wg sync.WaitGroup
	for i, u := range r.upstreams {
		wg.Add(1)
		go func(idx int, u dotUpstream) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(parent, 2500*time.Millisecond)
			defer cancel()
			start := time.Now()
			resp, err := r.exchangeUpstream(ctx, u, dotProbePacket)
			if err == nil && len(resp) >= 12 && resp[3]&0x0f == 0 {
				results[idx] = probeResult{upstream: u, latency: time.Since(start), ok: true}
			}
		}(i, u)
	}
	wg.Wait()
	var healthy []probeResult
	for _, res := range results {
		if res.ok {
			healthy = append(healthy, res)
		}
	}
	sort.Slice(healthy, func(i, j int) bool { return healthy[i].latency < healthy[j].latency })
	ordered := make([]dotUpstream, len(healthy))
	for i, h := range healthy {
		ordered[i] = h.upstream
	}
	r.ranked.Store(&ordered)
	if len(ordered) == 0 {
		return false, ""
	}
	return true, ordered[0].label
}

func (r *dotResolver) lookupCache(key dotCacheKey, txid []byte) []byte {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	entry, ok := r.cache[key]
	if !ok {
		return nil
	}
	if !time.Now().Before(entry.expires) {
		delete(r.cache, key)
		return nil
	}
	out := slices.Clone(entry.resp)
	out[0], out[1] = txid[0], txid[1]
	return out
}

func (r *dotResolver) storeCache(key dotCacheKey, resp []byte) {
	if len(resp) < 12 || resp[2]&0x02 != 0 { // don't cache truncated responses
		return
	}
	rcode := resp[3] & 0x0f
	if rcode != 0 && rcode != 3 { // only NOERROR and NXDOMAIN
		return
	}
	ttl := 30 * time.Second
	if rcode == 0 {
		if parsed := extractMinTTL(resp); parsed > 0 {
			ttl = min(systemDNSMaxTTL, max(systemDNSMinTTL, parsed))
		}
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	now := time.Now()
	if len(r.cache) >= systemDNSCacheMax {
		for k, v := range r.cache {
			if !now.Before(v.expires) {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= systemDNSCacheMax {
			clear(r.cache)
		}
	}
	r.cache[key] = dotCacheEntry{resp: slices.Clone(resp), expires: now.Add(ttl)}
}

func skipDNSName(b []byte, off int) (int, bool) {
	for i := 0; i < 128 && off < len(b); i++ {
		n := int(b[off])
		if n == 0 {
			return off + 1, true
		}
		if n&0xc0 == 0xc0 {
			if off+2 > len(b) {
				return 0, false
			}
			return off + 2, true
		}
		if n&0xc0 != 0 || off+1+n > len(b) {
			return 0, false
		}
		off += 1 + n
	}
	return 0, false
}

func extractMinTTL(b []byte) time.Duration {
	if len(b) < 12 {
		return 0
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	off := 12
	for range qd {
		var ok bool
		off, ok = skipDNSName(b, off)
		if !ok || off+4 > len(b) {
			return 0
		}
		off += 4
	}
	var best uint32
	found := false
	for range an {
		var ok bool
		off, ok = skipDNSName(b, off)
		if !ok || off+10 > len(b) {
			break
		}
		ttl := binary.BigEndian.Uint32(b[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10 + rdlen
		if off > len(b) {
			break
		}
		if !found || ttl < best {
			best = ttl
			found = true
		}
	}
	if !found {
		return 0
	}
	return time.Duration(best) * time.Second
}

func (r *dotResolver) answer(ctx context.Context, network string, query []byte) []byte {
	if len(query) < 12 || len(query) > systemDNSLimit || query[2]&0x80 != 0 {
		return nil
	}
	q, hasQ := readMCPQuestion(query)
	if hasQ && (q.host == "local" || strings.HasSuffix(q.host, ".local")) {
		return mcpDNSReply(query, q.end, 5)
	}
	limit := systemDNSLimit
	if network == "udp" {
		if hasQ {
			if l, ok := mcpQueryLimit(query, q); ok {
				limit = l
			} else {
				limit = 512
			}
		} else {
			limit = 512
		}
	}
	if hasQ {
		if cached := r.lookupCache(dotCacheKey{host: q.host, kind: q.kind}, query[:2]); cached != nil {
			if len(cached) <= limit {
				return cached
			}
			// Truncate flag for UDP when cached response exceeds client UDP buffer.
			trunc := mcpDNSReply(query, q.end, 0)
			trunc[2] |= 2
			return trunc
		}
	}
	var upstreams []dotUpstream
	if ptr := r.ranked.Load(); ptr != nil && len(*ptr) > 0 {
		upstreams = *ptr
	} else {
		upstreams = r.upstreams
	}
	budget, cancel := context.WithTimeout(ctx, systemDNSQueryBudget)
	defer cancel()
	for i, u := range upstreams {
		deadline, _ := budget.Deadline()
		per := min(2500*time.Millisecond, max(500*time.Millisecond, time.Until(deadline)/time.Duration(len(upstreams)-i)))
		attempt, done := context.WithTimeout(budget, per)
		resp, err := r.exchangeUpstream(attempt, u, query)
		done()
		if err == nil {
			if hasQ {
				r.storeCache(dotCacheKey{host: q.host, kind: q.kind}, resp)
			}
			if len(resp) > limit && hasQ {
				trunc := mcpDNSReply(query, q.end, 0)
				trunc[2] |= 2
				return trunc
			}
			return resp
		}
	}
	if hasQ {
		return mcpDNSReply(query, q.end, 2)
	}
	return mcpDNSReply(query, 12, 2)
}

func (r *dotResolver) serve(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener) {
	defer udp.Close()
	defer tcp.Close()
	defer r.closePools()
	local := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	if !local.Addr().IsLoopback() || tcp.Addr().(*net.TCPAddr).AddrPort() != local {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { udp.Close(); tcp.Close() })
	defer stop()
	var workers sync.WaitGroup
	slots := make(chan struct{}, 64)
	start := func(job func()) bool {
		select {
		case slots <- struct{}{}:
			workers.Go(func() { defer func() { <-slots }(); job() })
			return true
		default:
			return false
		}
	}
	workers.Go(func() {
		defer cancel()
		for {
			c, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			if !c.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() || !start(func() {
				defer c.Close()
				if c.SetDeadline(time.Now().Add(systemDNSQueryBudget)) != nil {
					return
				}
				for ctx.Err() == nil {
					b, err := readMCPFrame(c)
					if err != nil {
						return
					}
					resp := r.answer(ctx, "tcp", b)
					if resp == nil || writeMCPFrame(c, resp) != nil {
						return
					}
				}
			}) {
				c.Close()
			}
		}
	})
	buf := make([]byte, systemDNSLimit+1)
	for {
		n, peer, err := udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		if !peer.Addr().IsLoopback() || n > systemDNSLimit {
			continue
		}
		query := slices.Clone(buf[:n])
		start(func() {
			if resp := r.answer(ctx, "udp", query); resp != nil {
				_, _ = udp.WriteToUDPAddrPort(resp, peer)
			}
		})
	}
	cancel()
	workers.Wait()
}

func runSystemDNS(ctx context.Context) int {
	if os.Geteuid() == 0 {
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
	resolver := newDoTResolver(nil)
	go resolver.serve(ctx, udp, tcp)
	enc := json.NewEncoder(os.Stderr)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-timer.C:
		}
		ready, upstream := resolver.probeAll(ctx)
		if ctx.Err() != nil {
			return 0
		}
		if err := enc.Encode(systemDNSStatus{Ready: ready, Upstream: upstream}); err != nil {
			return 1
		}
		delay := systemDNSProbePeriod
		if !ready {
			delay = 5 * time.Second
		}
		timer.Reset(delay)
	}
}
