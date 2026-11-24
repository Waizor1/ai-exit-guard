package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const googleHost = "accounts.google.com"

var services = []string{"Claude", "ChatGPT", "Antigravity"}

type individualProxy struct {
	Endpoint proxySpec
	Expected string
}
type proxyPlan struct {
	Common   proxySpec
	Profiles map[string]individualProxy
}

func (p proxyPlan) valid() bool {
	if !p.Common.valid() {
		return false
	}
	for k, v := range p.Profiles {
		if k != "Claude" && k != "ChatGPT" && k != "Antigravity" {
			return false
		}
		if _, err := canonical(v.Expected); err != nil || !v.Endpoint.valid() {
			return false
		}
	}
	return true
}
func (p proxyPlan) endpoint(service string) proxySpec {
	if individual, ok := p.Profiles[service]; ok {
		return individual.Endpoint
	}
	return p.Common
}

func serviceForHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range claudeDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return "Claude"
		}
	}
	for _, d := range openAIDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return "ChatGPT"
		}
	}
	if aiHost(host) {
		return "Antigravity"
	}
	return ""
}

type serviceRelay struct {
	mu       sync.RWMutex
	routes   map[string]proxySpec
	activity *liveFlows
	mcp      *mcpRoutes
}

func (r *serviceRelay) configure(p proxyPlan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routes == nil {
		r.routes = make(map[string]proxySpec)
	}
	for _, name := range services {
		ep := p.endpoint(name)
		old, ok := r.routes[name]
		if ok && ep.Scheme == old.Scheme && ep.Host == old.Host && ep.Port == old.Port && ep.User == old.User && ep.Password == old.Password {
			continue
		}
		if ok {
			old.gate.set(time.Time{})
		}
		ep.gate = &relayGate{}
		ep.flows = r.activity
		r.routes[name] = ep
	}
}
func (r *serviceRelay) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.routes {
		s.gate.set(time.Time{})
	}
}
func (r *serviceRelay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" && req.URL.Path == "/guard.pac" {
		proxySpec{}.ServeHTTP(w, req)
		return
	}
	host, _, _ := net.SplitHostPort(req.Host)
	r.mu.RLock()
	s, ok := r.routes[serviceForHost(host)]
	r.mu.RUnlock()
	if !ok {
		if r.mcp.serve(w, req) {
			return
		}
		http.Error(w, "Destination outside AI route", 403)
		return
	}
	s.ServeHTTP(w, req)
}
func (r *serviceRelay) control(line string) string {
	verb, arg, _ := strings.Cut(line, " ")
	if verb == "config" {
		var next proxyPlan
		if json.Unmarshal([]byte(arg), &next) != nil || !next.valid() {
			return "ERROR"
		}
		r.configure(next)
		return "READY"
	}
	if verb == "0" {
		r.close()
		return "CLOSED"
	}
	deadline, err := strconv.ParseInt(arg, 10, 64)
	r.mu.RLock()
	s, ok := r.routes[verb]
	r.mu.RUnlock()
	if !ok || err != nil {
		return "ERROR"
	}
	if s.gate.set(time.Unix(deadline, 0)) {
		return "OPEN"
	}
	return "CLOSED"
}

var regionField = regexp.MustCompile(`(?i)<input\b[^>]*\bname=["']region["'][^>]*\bvalue=["']([A-Z]{2})["']`)

func googleRegion(ctx context.Context, s proxySpec) (string, error) {
	c := s.probeClient()
	defer c.CloseIdleConnections()
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || req.URL.Host != googleHost {
			return errors.New("unexpected sign-in redirect")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://accounts.google.com/ServiceLogin?hl=en", nil)
	if err != nil {
		return "", err
	}
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusGatewayTimeout {
		return "", errGatewayTimeout
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("Google HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 3<<20))
	if err != nil {
		return "", err
	}
	match := regionField.FindSubmatch(b)
	if len(match) != 2 {
		return "", errors.New("Google не сообщил страну")
	}
	return strings.ToUpper(string(match[1])), nil
}

func checkGoogle(ctx context.Context, ep proxySpec) result {
	r := result{Host: googleHost, Status: "unknown", Checked: time.Now().UTC().Format(time.RFC3339)}
	country, err := retryNetworkOnce(ctx, func() (string, error) { return googleRegion(ctx, ep) })
	if err != nil {
		r.Detail = "Не удалось проверить страну Google"
		return r
	}
	r.TraceCountry = country
	probe := ep.probeClient()
	defer probe.CloseIdleConnections()
	b, err := probeBody(ctx, probe, api+"/ip.json")
	var who struct{ IP string }
	if err != nil || json.Unmarshal(b, &who) != nil {
		return r
	}
	r.IP, err = canonical(who.IP)
	if err != nil {
		return r
	}
	r.AssessmentIP = r.IP
	c := checker{ctx: ctx, client: newClient()}
	defer c.client.CloseIdleConnections()
	r.Risk = c.general(r.IP).value
	var info enrichment
	info.lookup(ctx, c.client, r.IP)
	info.apply(&r)
	r.Status = "google"
	return r
}

func monitorPlan(ctx context.Context, p proxyPlan, writer io.Writer) int {
	enc := json.NewEncoder(writer)
	return collectPlan(ctx, p, func(r result) error { return enc.Encode(r) })
}

func collectPlan(ctx context.Context, p proxyPlan, emit func(result) error) int {
	out := make(chan result, 16)
	var wg sync.WaitGroup
	// Share IP123 trust and IPinfo lookups for services using the same endpoint.
	groups := map[proxySpec][]target{}
	for _, t := range targets {
		ep := p.endpoint(serviceForHost(t.host))
		groups[ep] = append(groups[ep], t)
	}
	for ep, ts := range groups {
		wg.Add(1)
		go func(ep proxySpec, ts []target) {
			defer wg.Done()
			probe := ep.probeClient()
			defer probe.CloseIdleConnections()
			c := checker{ctx: ctx, upstream: probe, client: newClient(), viaLocal: true}
			defer c.client.CloseIdleConnections()
			c.trace = func(ctx context.Context, addr string) ([]byte, error) { b, _, e := get(ctx, probe, addr); return b, e }
			for v := range c.resultsFor(ts) {
				out <- v
			}
		}(ep, ts)
	}
	wg.Add(1)
	go func() { defer wg.Done(); out <- checkGoogle(ctx, p.endpoint("Antigravity")) }()
	go func() { wg.Wait(); close(out) }()
	failed := 0
	for v := range out {
		if emit(v) != nil {
			failed = 1
		}
	}
	return failed
}

func servePlan(ctx context.Context, p proxyPlan, input *bufio.Scanner, ln net.Listener, activity *liveFlows) int {
	r := &serviceRelay{activity: activity, mcp: loadMCP(ctx)}
	r.configure(p)
	defer r.close()
	server := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 32768}
	go func() { <-ctx.Done(); server.Close() }()
	fmt.Println("READY")
	go func() {
		defer server.Close()
		defer r.close()
		for input.Scan() {
			reply := r.control(input.Text())
			fmt.Println(reply)
			if reply == "ERROR" {
				return
			}
		}
	}()
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		return 1
	}
	return 0
}
