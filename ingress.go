package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

const ingressIP = "127.0.0.2"

// These names are exclusive to AI services. Shared Google OAuth hosts are only
// accepted by the explicit relay, never redirected for the entire machine.
var mappedHosts = slices.Concat(aiDomains, []string{
	"www.claude.ai", "api.claude.ai", "api.anthropic.com", "platform.claude.com", "console.anthropic.com", "platform.claude.ai",
	"www.chatgpt.com", "ab.chatgpt.com", "ws.chatgpt.com", "chat.openai.com", "api.openai.com", "auth.openai.com",
	"auth0.openai.com", "platform.openai.com", "auth.chatgpt.com", "cdn.oaistatic.com", "files.oaiusercontent.com",
	geminiAPI,
})

type helloReader struct {
	net.Conn
	reader io.Reader
}

func (c helloReader) Read(p []byte) (int, error) { return c.reader.Read(p) }

// Only inspect the name from ClientHello. Never send a TLS alert or impersonate
// the origin. The complete, original TLS stream goes through Guard unchanged.
func (c helloReader) Write(p []byte) (int, error) { return len(p), nil }

func clientHelloName(client net.Conn, input io.Reader) (string, []byte) {
	var prefix bytes.Buffer
	var name string
	capture := helloReader{client, io.TeeReader(io.LimitReader(input, 65536), &prefix)}
	inspector := tls.Server(capture, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name = strings.ToLower(strings.TrimSuffix(h.ServerName, "."))
		return nil, errors.New("finished inspection")
	}})
	_ = inspector.Handshake()
	return name, prefix.Bytes()
}

func forwardTLS(client net.Conn, relay string) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(8 * time.Second))
	name, prefix := clientHelloName(client, client)
	if !slices.Contains(mappedHosts, name) {
		return
	}
	peer, err := net.DialTimeout("tcp4", relay, 2*time.Second)
	if err != nil {
		return
	}
	defer peer.Close()
	// The local relay can retry an upstream handshake once before replying
	// to CONNECT. Keep this socket open for both attempts.
	peer.SetDeadline(time.Now().Add(2*(upstreamDialTimeout+upstreamHandshakeTimeout) + probeRetryDelay + 2*time.Second))
	target := net.JoinHostPort(name, "443")
	if _, err = fmt.Fprintf(peer, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return
	}
	headers := &io.LimitedReader{R: peer, N: 32768}
	response := bufio.NewReaderSize(headers, 4096)
	res, err := http.ReadResponse(response, &http.Request{Method: "CONNECT"})
	if err != nil || res.StatusCode != http.StatusOK {
		return
	}
	headers.N = 1 << 62
	if _, err = peer.Write(prefix); err != nil {
		return
	}
	peer.SetDeadline(time.Time{})
	client.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { io.Copy(peer, client); peer.Close(); close(done) }()
	io.Copy(client, response)
	client.Close()
	<-done
}

func serveIngress(ctx context.Context, ln net.Listener, relay string) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	defer ln.Close()
	slots := make(chan struct{}, 128)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		addr, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok || !addr.IP.IsLoopback() {
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); forwardTLS(c, relay) }()
		default:
			c.Close()
		}
	}
}
