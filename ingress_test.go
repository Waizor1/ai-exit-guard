package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The only trust anchor is the test origin. Success means both directions of
// the original TLS stream made it intact through the local CONNECT relay.
func TestIngressUsesOnlyGuard(t *testing.T) {
	var count atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "through Guard") }))
	defer origin.Close()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "api.openai.com:443" {
			http.Error(w, "wrong destination", 403)
			return
		}
		count.Add(1)
		peer, e := net.Dial("tcp", origin.Listener.Addr().String())
		if e != nil {
			return
		}
		defer peer.Close()
		client, b, _ := w.(http.Hijacker).Hijack()
		defer client.Close()
		b.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		b.Flush()
		go func() { io.Copy(peer, client); peer.Close() }()
		io.Copy(client, peer)
	}))
	defer relay.Close()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveIngress(ctx, l, relay.Listener.Addr().String())
	root := x509.NewCertPool()
	root.AddCert(origin.Certificate())
	dial := func(name string) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", l.Addr().String(), &tls.Config{ServerName: name, InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
			_, e := s.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: root, DNSName: "example.com"})
			return e
		}})
	}
	c, e := dial("api.openai.com")
	if e != nil {
		t.Fatal(e)
	}
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\n\r\n")
	res, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		t.Fatal(e)
	}
	data, e := io.ReadAll(res.Body)
	res.Body.Close()
	c.Close()
	if e != nil || string(data) != "through Guard" {
		t.Fatal("TLS response mismatch", e)
	}
	if c, e = dial("example.org"); e == nil {
		c.Close()
		t.Fatal("accepted unrelated host")
	}
	if count.Load() != 1 {
		t.Fatal("unexpected CONNECT count", count.Load())
	}
	relay.Close()
	if c, e = dial("api.openai.com"); e == nil {
		c.Close()
		t.Fatal("request succeeded with Guard offline")
	}
}
func TestSystemNameParity(t *testing.T) {
	b, e := os.ReadFile("GuardRules.swift")
	if e != nil {
		t.Fatal(e)
	}
	_, s, ok := strings.Cut(string(b), "static let hosts = [")
	if !ok {
		t.Fatal("missing system names")
	}
	s, _, _ = strings.Cut(s, "]")
	names := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(s, -1)
	var got []string
	for _, m := range names {
		got = append(got, m[1])
	}
	if !reflect.DeepEqual(got, mappedHosts) {
		t.Fatal("macOS and Windows system routes disagree")
	}
}
