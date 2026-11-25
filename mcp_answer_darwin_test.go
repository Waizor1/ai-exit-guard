package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

func makeMCPTestQuery(host string, kind uint16) []byte {
	b := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(host, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, kind)
	return binary.BigEndian.AppendUint16(b, 1)
}

func mcpTestSockets(t *testing.T) (*net.UDPConn, *net.TCPListener) {
	t.Helper()
	// TCP and UDP use separate ephemeral port pools. Retry if another UDP
	// listener already owns the TCP-selected port.
	for range 32 {
		tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tcp.Addr().(*net.TCPAddr).Port})
		if err == nil {
			t.Cleanup(func() { tcp.Close(); udp.Close() })
			return udp, tcp
		}
		tcp.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatal(err)
		}
	}
	t.Fatal("no available UDP/TCP loopback port")
	return nil, nil
}

func mcpTestExchange(t *testing.T, network string, addr string, query []byte) []byte {
	t.Helper()
	c, err := net.DialTimeout(network, addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if network == "tcp" {
		if err := writeMCPFrame(c, query); err != nil {
			t.Fatal(err)
		}
		b, err := readMCPFrame(c)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4097)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestMCPAnswerLocalSockets(t *testing.T) {
	udp, tcp := mcpTestSockets(t)
	addr := tcp.Addr().String()
	var a mcpAnswers
	host := "inside.example"
	ip4 := netip.MustParseAddr("192.0.2.1")
	ip6 := netip.MustParseAddr("2001:db8::1")
	records := map[string][]netip.Addr{host: {ip4, ip6}}
	a.replace(records, originalDNS{}, time.Now().Add(8*time.Second))
	records[host][0] = netip.MustParseAddr("192.0.2.99")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.serve(ctx, udp, tcp) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("responder did not stop")
		}
	})
	for _, network := range []string{"udp", "tcp"} {
		for _, tc := range []struct {
			host string
			kind uint16
			code byte
			ip   netip.Addr
		}{
			{"Inside.Example", 1, 0, ip4}, {host, 28, 0, ip6}, {host, 65, 0, netip.Addr{}},
			{host, 64, 0, netip.Addr{}}, {"otherinside.example", 1, 5, netip.Addr{}},
			{"sub." + host, 252, 5, netip.Addr{}},
		} {
			q := makeMCPTestQuery(tc.host, tc.kind)
			b := mcpTestExchange(t, network, addr, q)
			if b[3]&15 != tc.code || !bytes.Equal(b[12:len(q)], q[12:]) {
				t.Fatalf("%s %s/%d bad reply %x", network, tc.host, tc.kind, b)
			}
			n := binary.BigEndian.Uint16(b[6:])
			if !tc.ip.IsValid() {
				if n != 0 {
					t.Fatal("unexpected records")
				}
				continue
			}
			rr := b[len(q):]
			if n != 1 || len(rr) != 12+len(tc.ip.AsSlice()) || !bytes.Equal(rr[12:], tc.ip.AsSlice()) || binary.BigEndian.Uint32(rr[6:]) > 7 {
				t.Fatalf("bad address or TTL: %x", rr)
			}
		}
	}
	a.replace(records, originalDNS{}, time.Now().Add(-time.Second))
	if b := mcpTestExchange(t, "udp", addr, makeMCPTestQuery(host, 1)); b[3]&15 != 2 || b[7] != 0 {
		t.Fatalf("stale reply %x", b)
	}
}

func TestMCPAnswerScopedForward(t *testing.T) {
	upUDP, upTCP := mcpTestSockets(t)
	udp, tcp := mcpTestSockets(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var a mcpAnswers
	a.replace(map[string][]netip.Addr{"inside.example": nil}, originalDNS{server: upUDP.LocalAddr().(*net.UDPAddr).AddrPort()}, time.Now().Add(time.Minute))
	done := make(chan struct{})
	go func() { defer close(done); a.serve(ctx, udp, tcp) }()
	defer func() { cancel(); <-done }()
	clean := makeMCPTestQuery("vpn.inside.example", 1)
	withOPT := append([]byte(nil), clean...)
	withOPT[11] = 1
	withOPT = append(withOPT, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 8, 0, 12, 0, 4, 1, 2, 3, 4)
	for _, network := range []string{"udp", "tcp"} {
		for _, mismatch := range []string{"", "id", "name", "type"} {
			seen := make(chan []byte, 1)
			go func() {
				var c *net.TCPConn
				var peer *net.UDPAddr
				var b []byte
				var err error
				if network == "tcp" {
					upTCP.SetDeadline(time.Now().Add(2 * time.Second))
					c, err = upTCP.AcceptTCP()
					if err == nil {
						defer c.Close()
						c.SetDeadline(time.Now().Add(time.Second))
						b, err = readMCPFrame(c)
					}
				} else {
					upUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
					b = make([]byte, 4096)
					var n int
					n, peer, err = upUDP.ReadFromUDP(b)
					b = b[:n]
				}
				seen <- b
				if err != nil || len(b) < 12 {
					return
				}
				resp := mcpDNSReply(b, len(b), 3)
				switch mismatch {
				case "id":
					resp[1]++
				case "name":
					resp[13] = 'z'
				case "type":
					resp[len(resp)-3] = 28
				}
				if c != nil {
					writeMCPFrame(c, resp)
				} else {
					upUDP.WriteToUDP(resp, peer)
				}
			}()
			resp := mcpTestExchange(t, network, tcp.Addr().String(), withOPT)
			if b := <-seen; !bytes.Equal(b, clean) {
				t.Fatalf("upstream received %x, expected %x", b, clean)
			}
			expected := byte(3)
			if mismatch != "" {
				expected = 2
			}
			if resp[3]&15 != expected || binary.BigEndian.Uint16(resp) != 0x1234 {
				t.Fatalf("%s/%s reply %x", network, mismatch, resp)
			}
		}
	}
}

func TestMCPAnswerRejectsMalformedQueries(t *testing.T) {
	clean := makeMCPTestQuery("inside.example", 1)
	for name, edit := range map[string]func([]byte) []byte{
		"extra question":  func(b []byte) []byte { b[5] = 2; return b },
		"embedded dot":    func(b []byte) []byte { b[14] = '.'; return b },
		"label pointer":   func(b []byte) []byte { b[12] = 0xc0; b[13] = 12; return b },
		"trailing data":   func(b []byte) []byte { return append(b, 0) },
		"non-IN":          func(b []byte) []byte { b[len(b)-1] = 3; return b },
		"bad EDNS option": func(b []byte) []byte { b[11] = 1; return append(b, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 1, 0) },
		"extra answer":    func(b []byte) []byte { b[7] = 1; return b },
		"opcode":          func(b []byte) []byte { b[2] |= 8; return b },
	} {
		var a mcpAnswers
		b := a.answer(context.Background(), "udp", netip.AddrPort{}, edit(append([]byte(nil), clean...)))
		if len(b) != 12 || b[3]&15 != 1 {
			t.Fatalf("%s: %x", name, b)
		}
	}
}

func TestMCPAnswerPacketAndLifetimeLimits(t *testing.T) {
	const host = "inside.example"
	var a mcpAnswers
	var ips []netip.Addr
	ip := netip.MustParseAddr("2001:db8::1")
	for range 300 {
		ips = append(ips, ip)
		ip = ip.Next()
	}
	a.replace(map[string][]netip.Addr{host: ips}, originalDNS{}, time.Now().Add(time.Hour))
	q := makeMCPTestQuery(host, 28)
	for network, limit := range map[string]int{"udp": 512, "tcp": mcpDNSLimit} {
		b := a.answer(context.Background(), network, netip.AddrPort{}, q)
		if b[2]&2 == 0 || len(b) > limit || binary.BigEndian.Uint32(b[len(q)+6:]) != 15 {
			t.Fatalf("%s unexpected truncated answer", network)
		}
	}
	if b := a.answer(context.Background(), "udp", netip.AddrPort{}, make([]byte, mcpDNSLimit+1)); b != nil {
		t.Fatal("accepted oversize datagram")
	}
	if _, err := readMCPFrame(bytes.NewReader([]byte{0x10, 1})); err == nil {
		t.Fatal("accepted oversize TCP frame")
	}
	local := netip.MustParseAddrPort("127.0.0.1:53053")
	a.replace(map[string][]netip.Addr{host: ips}, originalDNS{server: local}, time.Now().Add(time.Minute))
	q = makeMCPTestQuery("child."+host, 28)
	if b := a.answer(context.Background(), "udp", local, q); b[3]&15 != 2 {
		t.Fatal("forwarded back to self")
	}
}
