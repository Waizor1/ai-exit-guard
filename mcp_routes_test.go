package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rpcTransportFunc func(*http.Request) (*http.Response, error)

func (f rpcTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMCPRoutes(t *testing.T) {
	m := &mcpRoutes{local: map[string]bool{}, remote: map[string]bool{}, runtimeFile: filepath.Join(t.TempDir(), "runtime.json")}
	const registered = "http://127.0.0.1:7801/servers/tools/mcp"
	m.register(registered)
	m.register("https://mcp.example.org/mcp")
	m.register("https://api.openai.com/mcp")
	if !m.remote["mcp.example.org"] || m.remote["api.openai.com"] {
		t.Fatal("incorrect TLS registrations")
	}
	orig := localRPCTransport
	t.Cleanup(func() { localRPCTransport = orig })
	localRPCTransport = rpcTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer fixture" || r.Header.Get("Proxy-Authorization") != "" {
			t.Fatal("incorrect RPC headers")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("RPC OK"))}, nil
	})
	relay := &serviceRelay{mcp: m}
	relay.configure(proxyPlan{})
	send := func(method, url string, want int) {
		t.Helper()
		r := httptest.NewRequest(method, url, nil)
		r.Header.Set("Authorization", "Bearer fixture")
		r.Header.Set("Proxy-Authorization", "must not forward")
		w := httptest.NewRecorder()
		relay.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: %d", method, url, w.Code)
		}
		if want == 200 && w.Body.String() != "RPC OK" {
			t.Fatal("RPC response lost")
		}
	}
	send("POST", registered, 200)
	send("POST", registered+"?next=example.org", 403)
	send("POST", "http://127.0.0.1:7801/admin", 403)
	send("POST", "http://127.0.0.1:9090/mcp", 403)
	send("CONNECT", "api.openai.com:443", 503)
	send("CONNECT", "arbitrary.test:443", 403)
	send("CONNECT", "127.0.0.1:7801", 403)
	for _, port := range []string{"3773", "3774"} {
		origin := "http://127.0.0.1:" + port
		if err := os.WriteFile(m.runtimeFile, []byte(`{"origin":"`+origin+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		send("POST", origin+"/mcp", 200)
	}
	send("POST", "http://127.0.0.1:3773/mcp", 403)
}

type rpcHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h rpcHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

func TestMCPTLSChecksNameBeforeDial(t *testing.T) {
	for _, sni := range []string{"mcp.example.org", "api.openai.com", ""} {
		t.Run("sni_"+sni, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			var dialed string
			done := make(chan struct{})
			go func() {
				defer close(done)
				serveMCPTLS(rpcHijacker{httptest.NewRecorder(), server}, httptest.NewRequest("CONNECT", "mcp.example.org:443", nil), "mcp.example.org", func(_ context.Context, host string) (net.Conn, error) { dialed = host; return nil, io.EOF })
			}()
			var response bytes.Buffer
			rd := bufio.NewReader(client)
			for {
				l, e := rd.ReadString('\n')
				if e != nil {
					t.Fatal(e)
				}
				response.WriteString(l)
				if l == "\r\n" {
					break
				}
			}
			if !strings.HasPrefix(response.String(), "HTTP/1.1 200") {
				t.Fatal(response.String())
			}
			tc := tls.Client(client, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
			_ = tc.Handshake()
			<-done
			if (dialed != "") != (sni == "mcp.example.org") {
				t.Fatalf("unexpected dial %q", dialed)
			}
		})
	}
}

func TestMCPRegisteredTLSExchange(t *testing.T) {
	// Only borrow the certificate; the exchange below runs entirely over pipes.
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	cfg := cert.TLS.Clone()
	cert.Close()
	client, front := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(4 * time.Second))
	upstream, back := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveMCPTLS(rpcHijacker{httptest.NewRecorder(), front}, httptest.NewRequest("CONNECT", "mcp.example.org:443", nil), "mcp.example.org", func(_ context.Context, h string) (net.Conn, error) { return upstream, nil })
	}()
	got := make(chan string, 1)
	go func() {
		defer back.Close()
		server := tls.Server(back, cfg)
		server.SetDeadline(time.Now().Add(4 * time.Second))
		req, e := http.ReadRequest(bufio.NewReader(server))
		if e != nil {
			got <- e.Error()
			return
		}
		got <- req.URL.Path
		io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nMCP OK!")
	}()
	preface := bufio.NewReader(client)
	for {
		line, e := preface.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if line == "\r\n" {
			break
		}
	}
	tc := tls.Client(client, &tls.Config{ServerName: "mcp.example.org", InsecureSkipVerify: true})
	if _, e := io.WriteString(tc, "POST /mcp HTTP/1.1\r\nHost: mcp.example.org\r\nContent-Length: 0\r\n\r\n"); e != nil {
		t.Fatal(e)
	}
	req, _ := http.NewRequest("POST", "https://mcp.example.org/mcp", nil)
	resp, e := http.ReadResponse(bufio.NewReader(tc), req)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	client.Close()
	if e != nil || string(body) != "MCP OK!" || <-got != "/mcp" {
		t.Fatal("MCP round trip failed")
	}
	<-done
}
