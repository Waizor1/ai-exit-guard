package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func startFakeDoTServer(t *testing.T, handler func([]byte) []byte) (dotUpstream, *x509.CertPool, func()) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.test"},
		DNSNames:     []string{"dns.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					q, err := readMCPFrame(c)
					if err != nil {
						return
					}
					resp := handler(q)
					if resp == nil || writeMCPFrame(c, resp) != nil {
						return
					}
				}
			}(c)
		}
	}()
	return dotUpstream{addr: ln.Addr().String(), serverName: "dns.test", label: "test-dot"}, pool, func() {
		ln.Close()
		<-done
	}
}

func makeFakeAResponse(q []byte, ip [4]byte, ttl uint32) []byte {
	parsed, ok := readMCPQuestion(q)
	if !ok {
		return mcpDNSReply(q, 12, 1)
	}
	reply := mcpDNSReply(q, parsed.end, 0)
	reply = append(reply, 0xc0, 0x0c)
	reply = binary.BigEndian.AppendUint16(reply, 1)
	reply = binary.BigEndian.AppendUint16(reply, 1)
	reply = binary.BigEndian.AppendUint32(reply, ttl)
	reply = binary.BigEndian.AppendUint16(reply, 4)
	reply = append(reply, ip[:]...)
	binary.BigEndian.PutUint16(reply[6:8], 1)
	return reply
}

func TestDoTResolverFailsOverCachesAndRefusesLocal(t *testing.T) {
	var hits atomic.Int32
	good, pool, closeGood := startFakeDoTServer(t, func(q []byte) []byte {
		hits.Add(1)
		return makeFakeAResponse(q, [4]byte{104, 20, 23, 154}, 60)
	})
	defer closeGood()

	// Dead listener that accepts TCP and stalls (mimics broken 1.1.1.1:853 under VPN).
	stalled, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	go func() {
		for {
			c, err := stalled.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { time.Sleep(5 * time.Second); c.Close() }(c)
		}
	}()

	bad := dotUpstream{addr: stalled.Addr().String(), serverName: "dns.test", label: "bad-dot"}
	r := newDoTResolver([]dotUpstream{bad, good})
	r.tlsConfig = func(u dotUpstream) *tls.Config {
		return &tls.Config{ServerName: u.serverName, RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	defer r.closePools()

	ready, label := r.probeAll(context.Background())
	if !ready || label != "test-dot" {
		t.Fatalf("expected healthy test-dot upstream, got ready=%v label=%q", ready, label)
	}

	// Build a query for example.com IN A.
	q := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	before := hits.Load()
	resp1 := r.answer(context.Background(), "udp", q)
	if len(resp1) < 16 || resp1[0] != 0x12 || resp1[1] != 0x34 || resp1[3]&0x0f != 0 {
		t.Fatalf("unexpected first answer: %x", resp1)
	}
	if hits.Load() != before+1 {
		t.Fatalf("expected 1 upstream hit, got %d", hits.Load()-before)
	}

	// Second query with a different txid must hit cache without touching upstream.
	q2 := append([]byte(nil), q...)
	q2[0], q2[1] = 0xab, 0xcd
	resp2 := r.answer(context.Background(), "udp", q2)
	if len(resp2) != len(resp1) || resp2[0] != 0xab || resp2[1] != 0xcd {
		t.Fatalf("cached reply txid mismatch: %x", resp2)
	}
	if hits.Load() != before+1 {
		t.Fatalf("expected cache hit, got %d upstream hits", hits.Load()-before)
	}

	// .local must be refused (RCODE=5) so mDNS handles it.
	localQ := []byte{
		0x33, 0x44, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		3, 'm', 'a', 'c', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	localResp := r.answer(context.Background(), "udp", localQ)
	if len(localResp) < 12 || localResp[3]&0x0f != 5 {
		t.Fatalf("expected REFUSED for .local, got %x", localResp)
	}
}
