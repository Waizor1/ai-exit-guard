// The loopback listener handles only TLS tunnels to service domains. TLS stays end-to-end.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errProxyAuth = errors.New("Прокси отклонил логин или пароль.")

var localProxy = "127.0.0.1:39178"

var claudeDomains = []string{"claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com", "claudemcpcontent.com"}
var openAIDomains = []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "oaistatsig.com", "openaimerge.com"}
var aiDomains = slices.Concat(claudeDomains, openAIDomains, []string{
	"antigravity.google",
	"antigravity.google.com",
	"aicode.googleapis.com",
	"cloudcode-pa.googleapis.com",
	"daily-cloudcode-pa.googleapis.com",
	"jetski-webchannel.googleapis.com",
	"businessaicode.googleapis.com",
	"businessaicode.us.rep.googleapis.com",
	"businessaicode.eu.rep.googleapis.com",
	"businessaicode.mtls.googleapis.com",
	"antigravity-hub-auto-updater-974169037036.us-central1.run.app",
	"antigravity-ide-auto-updater-974169037036.us-central1.run.app",
})

// Shared Google services are accepted when a client explicitly uses Guard.
// The system PAC and Happ must leave these destinations on their existing route.
var explicitGoogleHosts = []string{
	"accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com", "play.googleapis.com", "auth.cloud.google",
	"identitytoolkit.googleapis.com", "securetoken.googleapis.com", "sts.googleapis.com",
	"generativelanguage.googleapis.com", "aiplatform.googleapis.com",
	"aiplatform.us.rep.googleapis.com", "aiplatform.eu.rep.googleapis.com", "aiplatform.mtls.googleapis.com",
	"discoveryengine.googleapis.com", "us-discoveryengine.googleapis.com", "eu-discoveryengine.googleapis.com",
	"discoveryengine.mtls.googleapis.com", "us-discoveryengine.mtls.googleapis.com", "eu-discoveryengine.mtls.googleapis.com",
}

type proxySpec struct {
	gate                         *relayGate
	flows                        *liveFlows
	Scheme, Host, User, Password string
	Port                         int
}

func (s proxySpec) endpoint() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }
func (s proxySpec) valid() bool {
	return (s.Scheme == "http" || s.Scheme == "https" || s.Scheme == "socks5") && s.Host != "" && !strings.ContainsAny(s.Host, " /@?#\r\n\t") && s.Port > 0 && s.Port <= 65535 && !(s.Host == "127.0.0.1" && s.Port == 39178) && len(s.User) <= 255 && len(s.Password) <= 255 && (s.Password == "" || s.User != "")
}
func aiHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if slices.Contains(explicitGoogleHosts, host) {
		return true
	}
	for _, domain := range aiDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
func pac() string {
	domains, _ := json.Marshal(aiDomains)
	return "function FindProxyForURL(url, host) { host=host.toLowerCase().replace(/\\.$/,''); var d=" + string(domains) + "; for(var i=0;i<d.length;i++) if(host===d[i] || dnsDomainIs(host,'.'+d[i])) return 'PROXY " + localProxy + "'; return 'DIRECT'; }"
}
func (s proxySpec) tunnel(ctx context.Context, host string) (net.Conn, error) {
	dial := net.Dialer{Timeout: 7 * time.Second}
	c, e := dial.DialContext(ctx, "tcp", s.endpoint())
	if e != nil {
		return nil, e
	}
	raw := c
	stopClose := context.AfterFunc(ctx, func() { raw.Close() })
	defer stopClose()
	c.SetDeadline(time.Now().Add(12 * time.Second))
	if s.Scheme == "https" {
		secure := tls.Client(c, &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12})
		c = secure
		e = secure.HandshakeContext(ctx)
	}
	if e == nil {
		if s.Scheme == "socks5" {
			e = s.socks(c, host)
		} else {
			authority := net.JoinHostPort(host, "443")
			req := http.Request{Method: "CONNECT", URL: &url.URL{Opaque: authority}, Host: authority, Header: make(http.Header)}
			if s.User != "" {
				req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.User+":"+s.Password)))
			}
			if e = req.Write(c); e == nil {
				var response *http.Response
				response, e = http.ReadResponse(bufio.NewReader(io.LimitReader(c, 65536)), &req)
				if e == nil && response.StatusCode != 200 {
					if response.StatusCode == http.StatusGatewayTimeout {
						e = errGatewayTimeout
					} else if response.StatusCode == 407 {
						e = errProxyAuth
					} else {
						e = errors.New("proxy refused tunnel")
					}
				}
			}
		}
	}
	if e != nil {
		c.Close()
		return nil, e
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
func (s proxySpec) socks(c net.Conn, host string) error {
	method := byte(0)
	if s.User != "" {
		method = 2
	}
	read := func(n int) ([]byte, error) { b := make([]byte, n); _, e := io.ReadFull(c, b); return b, e }
	if _, e := c.Write([]byte{5, 1, method}); e != nil {
		return e
	}
	b, e := read(2)
	if e != nil {
		return e
	}
	if b[0] != 5 || b[1] != method {
		return errors.New("SOCKS authentication method")
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(s.User))}, []byte(s.User)...)
		auth = append(auth, byte(len(s.Password)))
		auth = append(auth, []byte(s.Password)...)
		if _, e = c.Write(auth); e != nil {
			return e
		}
		b, e = read(2)
		if e != nil {
			return e
		}
		if b[0] != 1 || b[1] != 0 {
			return errProxyAuth
		}
	}
	msg := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	msg = append(msg, 1, 187)
	if _, e = c.Write(msg); e != nil {
		return e
	}
	b, e = read(4)
	if e != nil {
		return e
	}
	if b[0] != 5 || b[1] != 0 {
		return errors.New("SOCKS tunnel")
	}
	var n int
	switch b[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		b, e = read(1)
		if e != nil {
			return e
		}
		n = int(b[0])
	default:
		return errors.New("SOCKS reply")
	}
	_, e = read(n + 2)
	return e
}

func (s proxySpec) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/guard.pac" {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, pac())
		return
	}
	host, port, e := net.SplitHostPort(r.Host)
	if r.Method != "CONNECT" || e != nil || port != "443" || len(host) > 253 || (!aiHost(host) && host != "ip123.in") {
		http.Error(w, "Destination outside AI route", 403)
		return
	}
	if s.gate == nil {
		http.Error(w, "Guard is waiting for a check", http.StatusServiceUnavailable)
		return
	}
	window := s.gate.current()
	if window == nil {
		http.Error(w, "Guard has paused AI connections", http.StatusServiceUnavailable)
		return
	}
	connectCtx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(window, cancel)
	defer cancel()
	defer stop()
	peer, e := retryNetworkOnce(connectCtx, func() (net.Conn, error) {
		if err := window.Err(); err != nil {
			return nil, err
		}
		return s.tunnel(connectCtx, host)
	})
	if e != nil {
		if window.Err() != nil {
			http.Error(w, "Guard has paused AI connections", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "AI proxy unavailable", 502)
		return
	}
	defer peer.Close()
	if !s.gate.attach(window, peer) {
		http.Error(w, "Guard has paused AI connections", http.StatusServiceUnavailable)
		return
	}
	defer s.gate.remove(peer)
	client, buffer, e := w.(http.Hijacker).Hijack()
	if e != nil {
		return
	}
	defer client.Close()
	release := s.flows.track(r.RemoteAddr, host)
	defer release()
	if _, e = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
		return
	}
	if buffer.Flush() != nil {
		return
	}
	done := make(chan struct{})
	go func() { io.Copy(peer, buffer); peer.Close(); close(done) }()
	io.Copy(client, peer)
	client.Close()
	<-done
}

// Each host reports the exit independently. A rotating proxy cannot establish a single expected IP.
func (s proxySpec) probeClient() *http.Client {
	c := newClient()
	tr := c.Transport.(*http.Transport)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, p, e := net.SplitHostPort(addr)
		if e != nil || p != "443" || (!aiHost(h) && h != "ip123.in") {
			return nil, errors.New("unexpected host")
		}
		return s.tunnel(ctx, h)
	}
	return c
}

func verifyProxy(ctx context.Context, s proxySpec) (string, error) {
	return verifyTargets(ctx, s, targets)
}
func verifyTargets(ctx context.Context, s proxySpec, selected []target) (string, error) {
	c := s.probeClient()
	defer c.CloseIdleConnections()
	type observation struct {
		ip  string
		err error
	}
	exits := make(chan observation, len(selected))
	var wg sync.WaitGroup
	for _, t := range selected {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			address := "https://" + h + "/cdn-cgi/trace"
			b, _, err := get(ctx, c, address)
			if err != nil && !errors.Is(err, errProxyAuth) && ctx.Err() == nil {
				b, _, err = get(ctx, c, address)
			}
			if err != nil {
				exits <- observation{err: err}
				return
			}
			ip, _, e := traceExit(b, h)
			exits <- observation{ip: ip, err: e}
		}(t.host)
	}
	wg.Wait()
	close(exits)
	expected := ""
	var missing, rotating bool
	for obs := range exits {
		if errors.Is(obs.err, errProxyAuth) {
			return "", errProxyAuth
		}
		ip := obs.ip
		if ip == "" {
			missing = true
			continue
		}
		if expected != "" && expected != ip {
			rotating = true
		}
		expected = ip
	}
	if rotating {
		return "", errors.New("Прокси даёт разные IP для сервисов. Выберите статический выход.")
	}
	if missing || expected == "" {
		return "", errors.New("Не все четыре сервиса подтвердили выход. Проверьте протокол и доступность прокси.")
	}
	return expected, nil
}
func proxyCommand(ctx context.Context, mode string) int {
	var s proxySpec
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 8192), 8192)
	if !input.Scan() {
		return 1
	}
	var plan proxyPlan
	if err := json.Unmarshal(input.Bytes(), &plan); err != nil {
		return 1
	}
	modern := plan.Common.Host != ""
	if modern && !plan.valid() {
		return 1
	}
	if modern && mode == "proxy-monitor" {
		return monitorPlan(ctx, plan, os.Stdout)
	}
	if !modern && (json.Unmarshal(input.Bytes(), &s) != nil || !s.valid()) {
		fmt.Println("Проверьте формат адреса прокси.")
		return 1
	}
	if mode == "proxy-monitor" {
		probe := s.probeClient()
		defer probe.CloseIdleConnections()
		diagnostic := checker{ctx: ctx, client: newClient(), upstream: probe, viaLocal: true}
		diagnostic.trace = func(ctx context.Context, address string) ([]byte, error) {
			body, _, err := get(ctx, probe, address)
			return body, err
		}
		return diagnostic.emit()
	}
	if mode == "proxy-check" {
		var request struct{ CheckService string }
		if json.Unmarshal(input.Bytes(), &request) != nil {
			return 1
		}
		selected := targets
		if request.CheckService != "" {
			selected = nil
			for _, t := range targets {
				if serviceForHost(t.host) == request.CheckService {
					selected = append(selected, t)
				}
			}
			if request.CheckService != "Antigravity" && len(selected) == 0 {
				return 1
			}
		}
		var baseline string
		for i := 0; i < 3; i++ {
			var ip string
			var e error
			if request.CheckService == "Antigravity" {
				g := checkGoogle(ctx, s)
				ip = g.IP
				if ip == "" || g.TraceCountry == "" {
					e = errors.New("Не удалось проверить маршрут Google.")
				}
			} else {
				ip, e = verifyTargets(ctx, s, selected)
			}
			if e != nil {
				fmt.Println(e)
				return 1
			}
			if baseline != "" && ip != baseline {
				fmt.Println("Адрес меняется между проверками. Нужен статический прокси.")
				return 1
			}
			baseline = ip
		}
		fmt.Println(baseline)
		return 0
	}
	ln, e := net.Listen("tcp4", localProxy)
	if e != nil {
		fmt.Println("Локальный порт Guard уже занят.")
		return 1
	}
	if path := os.Getenv("AI_GUARD_ACTIVITY_SOCKET"); path != "" {
		s.flows = &liveFlows{peers: make(map[string]string)}
		listener, err := s.flows.publish(path)
		if err == nil {
			defer listener.Close()
		}
	}
	if modern {
		return servePlan(ctx, plan, input, ln, s.flows)
	}
	s.gate = &relayGate{}
	defer s.gate.set(time.Time{})
	server := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 32768}
	go func() { <-ctx.Done(); server.Close() }()
	fmt.Println("READY")
	go func() {
		defer server.Close()
		defer s.gate.set(time.Time{})
		for input.Scan() {
			deadline, err := strconv.ParseInt(input.Text(), 10, 64)
			if err != nil {
				return
			}
			if s.gate.set(time.Unix(deadline, 0)) {
				fmt.Println("OPEN")
			} else {
				fmt.Println("CLOSED")
			}
		}
	}()
	if e = server.Serve(ln); e != nil && e != http.ErrServerClosed {
		return 1
	}
	return 0
}
