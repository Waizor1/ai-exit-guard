package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const mcpDNSLimit = 4096
const mcpDNSTimeout = 3 * time.Second

type mcpAnswerPolicy struct {
	records      map[string][]netip.Addr
	original     originalDNS
	expires      time.Time
	checkForward func(context.Context, string) bool
}

type mcpAnswers struct {
	policy atomic.Pointer[mcpAnswerPolicy]
}

func (a *mcpAnswers) replace(records map[string][]netip.Addr, original originalDNS, expires time.Time) {
	a.replaceChecked(records, original, expires, nil)
}

func (a *mcpAnswers) replaceChecked(records map[string][]netip.Addr, original originalDNS, expires time.Time, check func(context.Context, string) bool) {
	p := &mcpAnswerPolicy{make(map[string][]netip.Addr, len(records)), original, expires, check}
	for h, ips := range records {
		p.records[h] = slices.Clone(ips)
	}
	a.policy.Store(p)
}

type mcpQuestion struct {
	host string
	kind uint16
	end  int
}

// A single first question has no preceding name to compress against. Reject
// pointers and literal dots within labels so suffix checks preserve label boundaries.
func readMCPQuestion(b []byte) (mcpQuestion, bool) {
	if len(b) < 12 || binary.BigEndian.Uint16(b[4:]) != 1 {
		return mcpQuestion{}, false
	}
	i := 12
	var labels []string
	for i < len(b) && i-12 < 255 {
		n := int(b[i])
		i++
		if n == 0 {
			if len(labels) == 0 || i+4 > len(b) || binary.BigEndian.Uint16(b[i+2:]) != 1 {
				break
			}
			return mcpQuestion{strings.ToLower(strings.Join(labels, ".")), binary.BigEndian.Uint16(b[i:]), i + 4}, true
		}
		if n > 63 || i+n > len(b) {
			break
		}
		label := b[i : i+n]
		for _, c := range label {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return mcpQuestion{}, false
			}
		}
		labels = append(labels, string(label))
		i += n
	}
	return mcpQuestion{}, false
}

// Accept a single optional EDNS(0) OPT and discard it before forwarding.
func mcpQueryLimit(b []byte, q mcpQuestion) (int, bool) {
	if binary.BigEndian.Uint16(b[2:]) & ^uint16(0x0130) != 0 || binary.BigEndian.Uint32(b[6:]) != 0 {
		return 0, false
	}
	switch binary.BigEndian.Uint16(b[10:]) {
	case 0:
		return 512, q.end == len(b)
	case 1:
		opt := b[q.end:]
		if len(opt) < 11 || opt[0] != 0 || binary.BigEndian.Uint16(opt[1:]) != 41 || opt[5] != 0 || opt[6] != 0 || int(binary.BigEndian.Uint16(opt[9:])) != len(opt)-11 {
			return 0, false
		}
		for options := opt[11:]; len(options) != 0; {
			if len(options) < 4 {
				return 0, false
			}
			n := int(binary.BigEndian.Uint16(options[2:]))
			if n > len(options)-4 {
				return 0, false
			}
			options = options[4+n:]
		}
		return min(mcpDNSLimit, max(512, int(binary.BigEndian.Uint16(opt[3:])))), true
	}
	return 0, false
}

func mcpDNSReply(b []byte, end int, code byte) []byte {
	resp := make([]byte, end)
	copy(resp[:2], b)
	resp[2], resp[3] = 0x80|b[2]&1, 0x80|code
	if end > 12 {
		resp[5] = 1
		copy(resp[12:], b[12:end])
	}
	return resp
}

func readMCPFrame(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(size[:])
	if n < 12 || n > mcpDNSLimit {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeMCPFrame(c net.Conn, b []byte) error {
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
	_, err := c.Write(append(frame, b...))
	return err
}

func forwardMCPQuestion(ctx context.Context, original originalDNS, network string, b []byte, q mcpQuestion) []byte {
	ctx, cancel := context.WithTimeout(ctx, mcpDNSTimeout)
	defer cancel()
	upstreams := original.endpoints()
	for i, upstream := range upstreams {
		deadline, _ := ctx.Deadline()
		attempt, finish := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(upstreams)-i))
		response := exchangeMCPQuestion(attempt, upstream, network, b, q)
		finish()
		if response != nil {
			return response
		}
	}
	return nil
}

func exchangeMCPQuestion(ctx context.Context, original originalDNS, network string, b []byte, q mcpQuestion) []byte {
	c, err := original.dial(ctx, network)
	if err != nil {
		return nil
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	if c.SetDeadline(deadline) != nil {
		return nil
	}
	// Only the ID, RD bit and the original single question go upstream.
	query := slices.Clone(b[:q.end])
	query[2] &= 1
	query[3] = 0
	clear(query[6:12])
	var resp []byte
	if network == "tcp" {
		if writeMCPFrame(c, query) != nil {
			return nil
		}
		resp, err = readMCPFrame(c)
	} else {
		if _, err = c.Write(query); err != nil {
			return nil
		}
		buf := make([]byte, mcpDNSLimit+1)
		var n int
		n, err = c.Read(buf)
		resp = buf[:n]
	}
	if err != nil || len(resp) > mcpDNSLimit || len(resp) < 12 || !bytes.Equal(resp[:2], query[:2]) || resp[2]&0xf8 != 0x80 {
		return nil
	}
	rq, ok := readMCPQuestion(resp)
	if !ok || rq.host != q.host || rq.kind != q.kind {
		return nil
	}
	return resp
}

func (a *mcpAnswers) answer(ctx context.Context, network string, local netip.AddrPort, b []byte) []byte {
	if len(b) < 12 || len(b) > mcpDNSLimit || b[2]&0x80 != 0 {
		return nil
	}
	q, ok := readMCPQuestion(b)
	if !ok {
		return mcpDNSReply(b, 12, 1)
	}
	limit, ok := mcpQueryLimit(b, q)
	if !ok {
		return mcpDNSReply(b, 12, 1)
	}
	if network == "tcp" {
		limit = mcpDNSLimit
	}
	p := a.policy.Load()
	if p == nil || !time.Now().Before(p.expires) {
		return mcpDNSReply(b, q.end, 2)
	}
	reply := mcpDNSReply(b, q.end, 0)
	if ips, exact := p.records[q.host]; exact {
		ttl := uint32(min(15, max(0, time.Until(p.expires)/time.Second)))
		for _, ip := range ips {
			if !(q.kind == 1 && ip.Is4() || q.kind == 28 && ip.Is6() && !ip.Is4In6()) {
				continue
			}
			data := ip.AsSlice()
			if len(reply)+12+len(data) > limit {
				reply[2] |= 2
				break
			}
			reply = append(reply, 0xc0, 0x0c)
			reply = binary.BigEndian.AppendUint16(reply, q.kind)
			reply = binary.BigEndian.AppendUint16(reply, 1)
			reply = binary.BigEndian.AppendUint32(reply, ttl)
			reply = binary.BigEndian.AppendUint16(reply, uint16(len(data)))
			reply = append(reply, data...)
			binary.BigEndian.PutUint16(reply[6:], binary.BigEndian.Uint16(reply[6:])+1)
		}
		return reply
	}
	if q.kind == 0 || q.kind == 41 || q.kind >= 249 && q.kind <= 255 {
		return mcpDNSReply(b, q.end, 5)
	}
	for host := range p.records {
		if !strings.HasSuffix(q.host, "."+host) {
			continue
		}
		if !p.original.server.IsValid() || p.original.server == local || (p.checkForward != nil && !p.checkForward(ctx, q.host)) {
			return mcpDNSReply(b, q.end, 2)
		}
		resp := forwardMCPQuestion(ctx, p.original, network, b, q)
		if resp == nil || a.policy.Load() != p || !time.Now().Before(p.expires) {
			return mcpDNSReply(b, q.end, 2)
		}
		if len(resp) > limit {
			reply[2] |= 2
			return reply
		}
		return resp
	}
	return mcpDNSReply(b, q.end, 5)
}

func (a *mcpAnswers) serve(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener) {
	defer udp.Close()
	defer tcp.Close()
	local := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	if !local.Addr().IsLoopback() || tcp.Addr().(*net.TCPAddr).AddrPort() != local {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { udp.Close(); tcp.Close() })
	defer stop()
	var workers sync.WaitGroup
	slots := make(chan struct{}, 32)
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
				if c.SetDeadline(time.Now().Add(mcpDNSTimeout)) != nil {
					return
				}
				for ctx.Err() == nil {
					b, err := readMCPFrame(c)
					if err != nil {
						return
					}
					resp := a.answer(ctx, "tcp", local, b)
					if resp == nil || writeMCPFrame(c, resp) != nil {
						return
					}
				}
			}) {
				c.Close()
			}
		}
	})
	buf := make([]byte, mcpDNSLimit+1)
	for {
		n, peer, err := udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		if !peer.Addr().IsLoopback() || n > mcpDNSLimit {
			continue
		}
		query := slices.Clone(buf[:n])
		start(func() {
			if resp := a.answer(ctx, "udp", local, query); resp != nil {
				_, _ = udp.WriteToUDPAddrPort(resp, peer)
			}
		})
	}
	cancel()
	workers.Wait()
}
