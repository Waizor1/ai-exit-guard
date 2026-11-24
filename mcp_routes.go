package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Local MCP requests are absolute-form HTTP proxy requests. Admit only the
// registered RPC URL, never a whole port, a CONNECT, or a redirect target.
type mcpRoutes struct {
	local       map[string]bool
	remote      map[string]bool
	runtimeFile string
	mu          sync.Mutex
	refresh     func(context.Context) (*mcpRoutes, bool)
	nextRefresh time.Time
}

func localRPC(u *url.URL) bool {
	return u != nil && u.Scheme == "http" && u.User == nil && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1") && u.Port() != "" && u.Port() != "39178" && (u.Path == "/mcp" || strings.HasSuffix(u.Path, "/mcp")) && u.EscapedPath() == u.Path && !strings.Contains(u.Path, "..") && u.RawQuery == "" && u.Fragment == ""
}

func (m *mcpRoutes) register(raw string) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil {
		return
	}
	if localRPC(u) {
		m.local[u.String()] = true
		return
	}
	host := u.Hostname()
	if u.Scheme == "https" && (u.Port() == "" || u.Port() == "443") && strings.Contains(host, ".") && net.ParseIP(host) == nil && !aiHost(host) && !strings.HasSuffix(host, ".") {
		m.remote[strings.ToLower(host)] = true
	}
}

func loadMCP(ctx context.Context) *mcpRoutes {
	if runtime.GOOS != "darwin" || os.Geteuid() == 0 {
		return nil
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil
	}
	m := &mcpRoutes{local: map[string]bool{}, remote: map[string]bool{}, runtimeFile: filepath.Join(home, ".t3", "userdata", "server-runtime.json")}
	m.refresh = func(ctx context.Context) (*mcpRoutes, bool) { return readMCPRegistry(ctx, home) }
	return m
}

func readMCPRegistry(ctx context.Context, home string) (*mcpRoutes, bool) {
	m := &mcpRoutes{local: map[string]bool{}, remote: map[string]bool{}}
	// Read the CLI's effective registration format. Discard credentials and
	// command definitions. This runs only in the unprivileged desktop relay.
	for _, bin := range []string{filepath.Join(home, ".local/bin/codex"), "/opt/homebrew/bin/codex", "/usr/local/bin/codex"} {
		if st, e := os.Stat(bin); e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, 6*time.Second)
		cmd := exec.CommandContext(bounded, bin, "mcp", "list", "--json")
		cmd.Dir = home
		data, err := cmd.Output()
		cancel()
		var servers []struct {
			Enabled   bool
			Transport struct{ Type, URL string }
		}
		if err == nil && json.Unmarshal(data, &servers) == nil {
			for _, s := range servers {
				if s.Enabled && s.Transport.Type == "streamable_http" {
					m.register(s.Transport.URL)
				}
			}
			return m, true
		}
	}
	return nil, false
}

// Load after READY so a slow Codex startup cannot hold up the model relay.
// Retry discovery after a failure. Discard stale entries if it fails.
func (m *mcpRoutes) registered(ctx context.Context, key string, remote bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refresh != nil && !time.Now().Before(m.nextRefresh) {
		found, ok := m.refresh(ctx)
		if ok {
			m.local, m.remote = found.local, found.remote
			m.nextRefresh = time.Now().Add(time.Minute)
		} else {
			m.local, m.remote = nil, nil
			m.nextRefresh = time.Now().Add(5 * time.Second)
		}
	}
	if remote {
		return m.remote[key]
	}
	return m.local[key]
}

func (m *mcpRoutes) localAllowed(ctx context.Context, u *url.URL) bool {
	if !localRPC(u) {
		return false
	}
	if m.registered(ctx, u.String(), false) {
		return true
	}
	if u.Path != "/mcp" || m.runtimeFile == "" {
		return false
	}
	// T3 can choose another port after restarting. Read its current origin.
	data, e := os.ReadFile(m.runtimeFile)
	var rec struct{ Origin string }
	return e == nil && json.Unmarshal(data, &rec) == nil && u.String() == rec.Origin+"/mcp"
}

var localRPCTransport http.RoundTripper = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext, ResponseHeaderTimeout: 20 * time.Second}

func (m *mcpRoutes) serve(w http.ResponseWriter, r *http.Request) bool {
	if m == nil {
		return false
	}
	if r.Method == http.MethodConnect {
		host, port, e := net.SplitHostPort(r.Host)
		if e != nil || port != "443" || !m.registered(r.Context(), strings.ToLower(host), true) || aiHost(host) {
			return false
		}
		serveMCPTLS(w, r, strings.ToLower(host), dialPublicMCP)
		return true
	}
	if r.Method != "GET" && r.Method != "POST" && r.Method != "DELETE" {
		return false
	}
	if !r.URL.IsAbs() || r.Host != r.URL.Host || !m.localAllowed(r.Context(), r.URL) || r.Header.Get("Origin") != "" || r.Header.Get("Upgrade") != "" {
		return false
	}
	proxy := httputil.ReverseProxy{Transport: localRPCTransport, Rewrite: func(p *httputil.ProxyRequest) {
		p.Out.Header.Del("Proxy-Authorization")
		// Avoid name resolution or proxy environment overrides for local requests.
		if p.Out.URL.Hostname() == "localhost" {
			p.Out.URL.Host = net.JoinHostPort("127.0.0.1", p.Out.URL.Port())
		}
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "Local MCP unavailable", 502) }}
	proxy.ServeHTTP(w, r)
	return true
}

var carrierNAT = netip.MustParsePrefix("100.64.0.0/10")

func dialPublicMCP(ctx context.Context, host string) (net.Conn, error) {
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil {
		return nil, e
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || carrierNAT.Contains(ip) {
			continue
		}
		// Dial the inspected address, without a second DNS lookup.
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
		if e == nil {
			return c, nil
		}
	}
	return nil, errors.New("no reachable public endpoint")
}

func serveMCPTLS(w http.ResponseWriter, r *http.Request, host string, dial func(context.Context, string) (net.Conn, error)) {
	client, b, e := http.NewResponseController(w).Hijack()
	if e != nil {
		return
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, e = b.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil || b.Flush() != nil {
		return
	}
	// A registered MCP hostname must not become a generic TLS tunnel. Match
	// ClientHello before sending any bytes upstream, including buffered bytes.
	name, prefix := clientHelloName(client, b.Reader)
	if name != host {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	peer, e := dial(ctx, host)
	if e != nil {
		return
	}
	defer peer.Close()
	peer.SetWriteDeadline(time.Now().Add(8 * time.Second))
	if _, e = peer.Write(prefix); e != nil {
		return
	}
	peer.SetWriteDeadline(time.Time{})
	client.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { io.Copy(peer, b.Reader); peer.Close(); close(done) }()
	io.Copy(client, peer)
	client.Close()
	<-done
}
