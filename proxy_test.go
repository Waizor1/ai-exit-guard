package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSelectiveTunnel(t *testing.T) {
	for _, h := range []string{"claude.ai", "API.ANTHROPIC.COM.", "auth.openai.com", "sub.chatgpt.com"} {
		if !aiHost(h) {
			t.Fatalf("expected route %s", h)
		}
	}
	for _, h := range []string{"evilchatgpt.com", "openai.com.example.org", "example.com", "127.0.0.1"} {
		if aiHost(h) {
			t.Fatalf("unexpected route %s", h)
		}
	}
	for _, kind := range []string{"http", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			ln, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			h, p, _ := net.SplitHostPort(ln.Addr().String())
			port, _ := strconv.Atoi(p)
			spec := proxySpec{Scheme: kind, Host: h, Port: port, User: "demo", Password: "local"}
			spec.gate = &relayGate{}
			spec.gate.set(time.Now().Add(time.Minute))
			defer spec.gate.set(time.Time{})
			spec.flows = &liveFlows{peers: make(map[string]string)}
			done := make(chan bool, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					done <- false
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				b := bufio.NewReader(c)
				ok := false
				if kind == "http" {
					r, err := http.ReadRequest(b)
					ok = err == nil && r.Host == "api.openai.com:443" && r.Header.Get("Proxy-Authorization") == "Basic ZGVtbzpsb2NhbA=="
					io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
				} else {
					read := func(n int) string { x := make([]byte, n); _, _ = io.ReadFull(b, x); return string(x) }
					ok = read(3) == "\x05\x01\x02"
					c.Write([]byte{5, 2})
					ok = ok && read(12) == "\x01\x04demo\x05local"
					c.Write([]byte{1, 0})
					ok = ok && read(5) == "\x05\x01\x00\x03\x0e" && read(16) == "api.openai.com\x01\xbb"
					c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				}
				line, _ := b.ReadString('\n')
				io.WriteString(c, "pong\n")
				done <- ok && line == "ping\n"
			}()
			local := httptest.NewServer(spec)
			defer local.Close()
			c, e := net.DialTimeout("tcp", strings.TrimPrefix(local.URL, "http://"), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(4 * time.Second))
			io.WriteString(c, "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
			r := bufio.NewReader(c)
			response, e := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
			if e != nil || response.StatusCode != 200 {
				t.Fatalf("connect: %v %v", response, e)
			}
			if got := spec.flows.snapshot()[c.LocalAddr().String()]; got != "api.openai.com" {
				t.Fatalf("active tunnel not attributed: %q", got)
			}
			io.WriteString(c, "ping\n")
			reply, _ := r.ReadString('\n')
			if reply != "pong\n" || !<-done {
				t.Fatal("tunnel did not pass traffic/authentication")
			}
		})
	}
}
func TestProxyDoesNotFallBack(t *testing.T) {
	s := proxySpec{Scheme: "http", Host: "127.0.0.1", Port: 0}
	if _, err := s.tunnel(context.Background(), "claude.ai"); err == nil {
		t.Fatal("unexpected direct connection")
	}
	for _, host := range []string{"example.com:443", "claude.ai:22"} {
		r := httptest.NewRequest("CONNECT", "http://localhost", nil)
		r.Host = host
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}

func TestAntigravityRouting(t *testing.T) {
	system := "daily-cloudcode-pa.googleapis.com"
	if !aiHost(system) || !strings.Contains(pac(), system) {
		t.Fatal("Antigravity backend must route via PAC; shared sign-in requires explicit proxy")
	}
	for _, host := range []string{"oauth2.googleapis.com", "www.googleapis.com", "play.googleapis.com"} {
		if !aiHost(host) || strings.Contains(pac(), host) {
			t.Fatalf("shared Google sign-in host %s must be accepted only by explicitly proxied clients", host)
		}
	}
	for _, host := range []string{"www.googleapis.com.example.org", "sub.www.googleapis.com", "accounts.google.com.example.org", "x.oauth2.googleapis.com", "drive.google.com", "mail.google.com", "unknown.googleapis.com", "example.run.app"} {
		if aiHost(host) {
			t.Fatal("unexpected Google route", host)
		}
	}
}

func TestPACScopesSharedGoogleToItsClient(t *testing.T) {
	for _, path := range []string{"/guard.pac", "/antigravity.pac"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		(&serviceRelay{}).ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "api.anthropic.com") && !strings.Contains(w.Body.String(), "anthropic.com") {
			t.Fatal(path, w.Code)
		}
		if strings.Contains(w.Body.String(), googleHost) != (path == "/antigravity.pac") {
			t.Fatal("Google sign-in leaked outside its app", path)
		}
		for _, h := range []string{"github.com", "opencode.ai", "models.opencode.ai", "registry.npmjs.org"} {
			if strings.Contains(w.Body.String(), h) {
				t.Fatal("non-AI tool captured", h)
			}
		}
	}
}
