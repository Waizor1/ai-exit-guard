// AI Exit Guard diagnostic. Outbound anonymous HTTPS GETs only.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const api = "https://ip123.in/api/v2"

type target struct{ host, product string }

var targets = []target{{"claude.ai", "claude"}, {"api.anthropic.com", "claude"}, {"chatgpt.com", "chatgpt"}, {"api.openai.com", "chatgpt"}}

type result struct {
	Host, IP, AssessmentIP, Status, Detail, RiskDetail, Checked string
	TraceCountry, Country, Network, InfoDetail                  string
	Signals                                                     []string
	Trust, Risk                                                 *float64
	InfoChecked                                                 bool
}
type trustResult struct {
	ip     string
	scores map[string]struct {
		Score *float64 `json:"trust_score"`
	}
	err error
}
type envelope struct {
	Code *int
	Data json.RawMessage
}

func unpack(b []byte, into any) error {
	var e envelope
	if json.Unmarshal(b, &e) != nil || e.Code == nil || *e.Code != 0 || len(e.Data) == 0 {
		return errors.New("формат ответа IP123 изменился")
	}
	return json.Unmarshal(e.Data, into)
}
func newClient() *http.Client {
	tr := &http.Transport{ForceAttemptHTTP2: true, DialContext: (&net.Dialer{Timeout: 7 * time.Second}).DialContext, TLSHandshakeTimeout: 6 * time.Second, ResponseHeaderTimeout: 7 * time.Second}
	return &http.Client{Transport: tr, Timeout: 11 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func get(ctx context.Context, c *http.Client, addr string) ([]byte, net.Conn, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", addr, nil)
	if err != nil {
		return nil, nil, err
	}
	q := req.URL.Query()
	q.Set("_", strconv.FormatInt(time.Now().UnixNano(), 10))
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Cache-Control", "no-cache, no-store")
	var conn net.Conn
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { conn = i.Conn }}))
	r, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", r.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if len(b) > 65536 {
		return nil, nil, errors.New("слишком большой ответ")
	}
	return b, conn, err
}
func canonical(raw string) (string, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" {
		return "", errors.New("внешний IP отсутствует")
	}
	return ip.Unmap().String(), nil
}
func traceExit(b []byte, host string) (string, string, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			if _, duplicate := fields[k]; duplicate {
				return "", "", errors.New("неоднозначный ответ trace")
			}
			fields[k] = strings.TrimSpace(v)
		}
	}
	if fields["h"] != host {
		return "", "", errors.New("домен не подтвердил trace")
	}
	ip, err := canonical(fields["ip"])
	return ip, fields["loc"], err
}
func trustAt(ctx context.Context, c *http.Client, base string) (v trustResult) {
	b, first, err := get(ctx, c, base+"/ip.json")
	if err != nil {
		v.err = err
		return
	}
	var who struct{ IP string }
	if err = json.Unmarshal(b, &who); err != nil {
		v.err = err
		return
	}
	if v.ip, err = canonical(who.IP); err != nil {
		v.err = err
		return
	}
	b, second, err := get(ctx, c, base+"/ai_trust")
	if err != nil {
		v.err = err
		return
	}
	if first == nil || first != second {
		v.err = errors.New("IP123 сменил соединение во время проверки")
		return
	}
	v.err = unpack(b, &v.scores)
	return
}
func valid(n *float64) bool { return n != nil && *n >= 0 && *n <= 100 }
func decodeRisk(b []byte, ip string) (*float64, error) {
	var data struct {
		IP   string
		Risk *float64 `json:"fraud_score"`
	}
	if err := unpack(b, &data); err != nil {
		return nil, err
	}
	returned, err := canonical(data.IP)
	if err != nil || returned != ip {
		return nil, errors.New("IP в ответе IP123 отличается")
	}
	if !valid(data.Risk) {
		return nil, errors.New("общая оценка отсутствует")
	}
	return data.Risk, nil
}
func describe(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "ошибка DNS"
	}
	var e net.Error
	if errors.As(err, &e) && e.Timeout() {
		return "тайм-аут"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "соединение закрыто"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "сброс соединения"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "соединение отклонено"
	}
	var cert x509.UnknownAuthorityError
	if errors.As(err, &cert) {
		return "ошибка сертификата"
	}
	var u *url.Error
	if errors.As(err, &u) {
		return "ошибка HTTPS"
	}
	return err.Error()
}
func classify(r *result, p string, t trustResult) {
	r.AssessmentIP = t.ip
	if t.err != nil {
		r.Status = "unknown"
		r.Detail = "IP123: " + describe(t.err)
		return
	}
	if r.IP != t.ip {
		r.Status = "split"
		r.Detail = "IP123 оценил другой выход"
		return
	}
	s := t.scores[p].Score
	if !valid(s) {
		r.Status = "unknown"
		r.Detail = "Trust Score отсутствует"
		return
	}
	r.Trust = s
	switch {
	case *s <= 100.0/3:
		r.Status = "red"
		r.Detail = "Высокий риск IP123"
	case *s <= 200.0/3:
		r.Status = "amber"
		r.Detail = "Средняя оценка доверия"
	default:
		r.Status = "green"
		r.Detail = "Высокая оценка доверия"
	}
}

type riskReport struct {
	value *float64
	err   error
}
type checker struct {
	ctx      context.Context
	client   *http.Client
	trace    func(context.Context, string) ([]byte, error)
	upstream *http.Client
	observed func(result)
	viaLocal bool
	once     sync.Once
	trust    trustResult
	risk     sync.Map
}

func (c *checker) general(ip string) riskReport {
	raw, _ := c.risk.LoadOrStore(ip, sync.OnceValue(func() riskReport {
		address := api + "/search_ip_page?ip=" + url.QueryEscape(ip)
		b, _, err := get(c.ctx, c.client, address)
		var temporary net.Error
		if errors.As(err, &temporary) && temporary.Timeout() && c.ctx.Err() == nil {
			b, _, err = get(c.ctx, c.client, address)
		}
		if err != nil {
			return riskReport{err: err}
		}
		value, err := decodeRisk(b, ip)
		return riskReport{value, err}
	}))
	return raw.(func() riskReport)()
}

// Use the same macOS TLS client for every domain probe and ignore personal curl settings.
func systemTrace(parent context.Context, address string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 48*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "/usr/bin/curl", "--disable", "--noproxy", "*", "--fail",
		"--silent", "--connect-timeout", "5", "--max-time", "10", "--retry", "3",
		"--retry-all-errors", "--retry-delay", "1", "--max-filesize", "65536",
		"--header", "Cache-Control: no-store", address+"?_="+strconv.FormatInt(time.Now().UnixNano(), 10))
	body, err := probe.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 28 {
			return nil, errors.New("тайм-аут")
		}
		return nil, errors.New("домен не ответил на проверку")
	}
	if len(body) > 65536 {
		return nil, errors.New("слишком большой ответ")
	}
	return body, nil
}

// Prefer the native network stack. Retry only this host; never borrow another host's exit.
func installedTrace(ctx context.Context, address string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(filepath.Dir(exe), "../Helpers/TraceProbe")
	bounded, cancel := context.WithTimeout(ctx, 47*time.Second)
	defer cancel()
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		body, commandErr := exec.CommandContext(bounded, binary, address).Output()
		if commandErr == nil {
			if _, _, err := traceExit(body, u.Hostname()); err == nil {
				return body, nil
			}
		}
		if errors.Is(commandErr, os.ErrNotExist) {
			break
		}
		if bounded.Err() != nil {
			return nil, bounded.Err()
		}
	}
	return systemTrace(bounded, address)
}

func (c *checker) run(dst target) (r result) {
	r.Host = dst.host
	r.Status = "unknown"

	traceURL := "https://" + dst.host + "/cdn-cgi/trace"
	b, err := c.trace(c.ctx, traceURL)
	if c.viaLocal && err != nil && c.ctx.Err() == nil {
		// Retry an unanswered request on the same route. A returned address is always evaluated.
		b, err = c.trace(c.ctx, traceURL)
	}
	r.Checked = time.Now().Format(time.RFC3339)
	if err == nil {
		r.IP, r.TraceCountry, err = traceExit(b, dst.host)
	}
	if err != nil {
		r.Detail = "Проверка домена: " + describe(err)
		return
	}
	if c.observed != nil {
		observation := r
		observation.Status = "measuring"
		c.observed(observation)
	}
	risk := make(chan riskReport, 1)
	go func(ip string) { risk <- c.general(ip) }(r.IP)
	c.once.Do(func() {
		tc := newClient()
		if c.upstream != nil {
			tc = c.upstream
		} else if c.viaLocal {
			tc.Transport.(*http.Transport).Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: localProxy})
		}
		defer tc.CloseIdleConnections()
		c.trust = trustAt(c.ctx, tc, api)
		var temporary net.Error
		if errors.As(c.trust.err, &temporary) && temporary.Timeout() && c.ctx.Err() == nil {
			tc.CloseIdleConnections()
			c.trust = trustAt(c.ctx, tc, api)
		}
	})
	classify(&r, dst.product, c.trust)
	x := <-risk
	r.Risk = x.value
	if x.err != nil {
		r.RiskDetail = describe(x.err)
	}
	return
}

type networkInfo struct {
	Country, Org, IP string
	Anycast          *bool
	Privacy          *struct{ VPN, Proxy, Tor, Relay, Hosting *bool }
}

func (n networkInfo) signals() []string {
	var labels []string
	if n.Anycast != nil && *n.Anycast {
		labels = append(labels, "Anycast")
	}
	if p := n.Privacy; p != nil {
		for _, flag := range []struct {
			name  string
			value *bool
		}{{"VPN", p.VPN}, {"Proxy", p.Proxy}, {"Tor", p.Tor}, {"Relay", p.Relay}, {"Hosting", p.Hosting}} {
			if flag.value != nil && *flag.value {
				labels = append(labels, flag.name)
			}
		}
	}
	return labels
}

func decodeInfo(b []byte, requested string) (networkInfo, error) {
	var info networkInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return networkInfo{}, err
	}
	ip, err := canonical(info.IP)
	if err != nil || ip != requested {
		return networkInfo{}, errors.New("IPinfo вернул другой адрес")
	}
	if info.Org == "" && info.Country == "" {
		return networkInfo{}, errors.New("нет сведений о сети")
	}
	return info, nil
}

type enrichment struct {
	once sync.Once
	info networkInfo
	err  error
}

func (c *checker) results() <-chan result {
	out := make(chan result, 2*len(targets))
	var wg sync.WaitGroup
	var cached sync.Map
	if c.upstream != nil {
		c.observed = func(r result) { out <- r }
	}
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			r := c.run(t)
			out <- r
			if r.IP == "" {
				return
			}
			raw, _ := cached.LoadOrStore(r.IP, &enrichment{})
			e := raw.(*enrichment)
			e.once.Do(func() {
				b, _, err := get(c.ctx, c.client, "https://ipinfo.io/"+r.IP+"/json")
				if err == nil {
					e.info, err = decodeInfo(b, r.IP)
				}
				e.err = err
			})
			r.InfoChecked = e.err == nil
			if e.err != nil {
				r.InfoDetail = describe(e.err)
			} else {
				r.Country = e.info.Country
				r.Network = e.info.Org
				r.Signals = e.info.signals()
			}
			out <- r
		}(t)
	}
	go func() { wg.Wait(); close(out) }()
	return out
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) == 2 && os.Args[1] == "activity" {
		if activityCommand(ctx, os.Getenv("AI_GUARD_ACTIVITY_SOCKET")) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && (os.Args[1] == "proxy-check" || os.Args[1] == "proxy-serve" || os.Args[1] == "proxy-monitor") {
		os.Exit(proxyCommand(ctx, os.Args[1]))
	}
	c := checker{ctx: ctx, client: newClient(), trace: installedTrace}
	if len(os.Args) == 2 && (os.Args[1] == "routed" || os.Args[1] == "local-routed") {
		c.viaLocal = true
		c.trace = func(ctx context.Context, addr string) ([]byte, error) {
			if os.Args[1] == "local-routed" {
				client := newClient()
				defer client.CloseIdleConnections()
				client.Transport.(*http.Transport).Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: localProxy})
				b, _, err := get(ctx, client, addr)
				return b, err
			}
			// Measure the effective system route, including its PAC selection, as seen by URLSession.
			exe, err := os.Executable()
			if err != nil {
				return nil, err
			}
			deadline, cancel := context.WithTimeout(ctx, 19*time.Second)
			defer cancel()
			return exec.CommandContext(deadline, filepath.Join(filepath.Dir(exe), "../Helpers/TraceProbe"), addr).Output()
		}
	}
	os.Exit(c.emit())
}

func (c *checker) emit() int {
	defer c.client.CloseIdleConnections()
	enc := json.NewEncoder(os.Stdout)
	for r := range c.results() {
		if err := enc.Encode(r); err != nil {
			return 1
		}
	}
	return 0
}
