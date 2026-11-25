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
	"net/url"
	"regexp"
	"slices"
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
	Common       proxySpec
	Profiles     map[string]individualProxy
	CommonPaused bool
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
func (p proxyPlan) activeEndpoint(service string) (proxySpec, bool) {
	if individual, ok := p.Profiles[service]; ok {
		return individual.Endpoint, true
	}
	return p.Common, !p.CommonPaused
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
	mu        sync.RWMutex
	routes    map[string]proxySpec
	activity  *liveFlows
	proxyOnly bool
}

func (r *serviceRelay) configure(p proxyPlan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routes == nil {
		r.routes = make(map[string]proxySpec)
	}
	for _, name := range services {
		ep, active := p.activeEndpoint(name)
		old, ok := r.routes[name]
		if !active {
			if ok {
				old.gate.set(time.Time{})
				delete(r.routes, name)
			}
			continue
		}
		if ok && ep.Scheme == old.Scheme && ep.Host == old.Host && ep.Port == old.Port && ep.User == old.User && ep.Password == old.Password {
			continue
		}
		if ok {
			old.gate.set(time.Time{})
		}
		ep.gate = &relayGate{}
		if r.proxyOnly {
			ep.gate.proxyOnly()
		}
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
	if servePAC(w, req) {
		return
	}
	host, _, _ := net.SplitHostPort(req.Host)
	r.mu.RLock()
	service := serviceForHost(host)
	s, ok := r.routes[service]
	r.mu.RUnlock()
	if service == "" {
		http.Error(w, "Destination outside AI route", 403)
		return
	}
	if !ok {
		r.activity.record(host, "blocked")
		http.Error(w, "Common proxy is paused", http.StatusServiceUnavailable)
		return
	}
	s.ServeHTTP(w, req)
}
func (r *serviceRelay) control(line string) string {
	payload, hasDeadlines := strings.CutPrefix(line, "mode guarded ")
	if line == "mode proxy-only" || line == "mode guarded" || hasDeadlines {
		var deadlines map[string]int64
		if hasDeadlines && json.Unmarshal([]byte(payload), &deadlines) != nil {
			return "ERROR"
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		enabled := line == "mode proxy-only"
		if enabled == r.proxyOnly {
			return "READY"
		}
		r.proxyOnly = enabled
		for service, route := range r.routes {
			if r.proxyOnly {
				route.gate.proxyOnly()
			} else {
				route.gate.set(time.Unix(deadlines[service], 0))
			}
		}
		return "READY"
	}
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
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.proxyOnly {
			return "OPEN"
		}
		for _, s := range r.routes {
			s.gate.set(time.Time{})
		}
		return "CLOSED"
	}
	deadline, err := strconv.ParseInt(arg, 10, 64)
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.routes[verb]
	if err != nil || !slices.Contains(services, verb) {
		return "ERROR"
	}
	if !ok {
		return "CLOSED"
	}
	// Diagnostics queued before a mode change must not close a working tunnel.
	if r.proxyOnly {
		return "OPEN"
	}
	if s.gate.set(time.Unix(deadline, 0)) {
		return "OPEN"
	}
	return "CLOSED"
}

var regionField = regexp.MustCompile(`(?i)<input\b[^>]*\bname=["']region["'][^>]*\bvalue=["']([A-Z]{2})["']`)

func googleRegion(ctx context.Context, upstream *http.Client) (string, error) {
	c := *upstream
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
	if len(match) != 2 || strings.EqualFold(string(match[1]), "XX") {
		return "", errors.New("Google не сообщил страну")
	}
	return strings.ToUpper(string(match[1])), nil
}

const fallbackIdentityHost = "www.cloudflare.com"

// Allow both bounded HTTP attempts to finish even if the first hits its 11-second timeout.
const googleMeasurementTimeout = 24 * time.Second

func googleExitIP(ctx context.Context, probe *http.Client) (ip string, fromIP123 bool, err error) {
	// Reserve time for the independent identity source even when IP123 stalls.
	primary, cancel := context.WithTimeout(ctx, 5*time.Second)
	body, _, err := get(primary, probe, api+"/ip.json")
	cancel()
	if errors.Is(err, errProxyAuth) {
		return "", false, errProxyAuth
	}
	var who struct{ IP string }
	if err == nil && json.Unmarshal(body, &who) == nil {
		if ip, err := canonical(who.IP); err == nil {
			return ip, true, nil
		}
	}
	body, err = probeBody(ctx, probe, "https://"+fallbackIdentityHost+"/cdn-cgi/trace")
	if err == nil {
		ip, _, err = traceExit(body, fallbackIdentityHost)
	}
	return ip, false, err
}

// Google supplies the country. Both identity sources use the same proxy transport.
func measureGoogle(parent context.Context, probe *http.Client) (profileMeasurement, bool, error) {
	ctx, cancel := context.WithTimeout(parent, googleMeasurementTimeout)
	defer cancel()
	type regionResult struct {
		country string
		err     error
	}
	regions := make(chan regionResult, 1)
	go func() {
		country, err := retryNetworkOnce(ctx, func() (string, error) { return googleRegion(ctx, probe) })
		regions <- regionResult{country, err}
	}()
	ip, primary, err := googleExitIP(ctx, probe)
	region := <-regions
	row := profileMeasurement{IP: ip, Country: region.country}
	if errors.Is(err, errProxyAuth) || errors.Is(region.err, errProxyAuth) {
		return row, primary, errProxyAuth
	}
	if region.err != nil {
		// URL errors may contain a redirect URL or private upstream address.
		var requestError *url.Error
		if errors.As(region.err, &requestError) {
			if requestError.Timeout() {
				return row, primary, errors.New("Истекло время проверки страны Google.")
			}
			return row, primary, errors.New("Не удалось открыть страницу входа Google через прокси.")
		}
		return row, primary, fmt.Errorf("Проверка страны Google: %w", region.err)
	}
	if err != nil {
		return row, primary, errors.New("IP123 и Cloudflare не подтвердили внешний IP через прокси.")
	}
	return row, primary, nil
}

func checkGoogle(ctx context.Context, ep proxySpec) result {
	r := result{Host: googleHost, Status: "unknown", Checked: time.Now().UTC().Format(time.RFC3339)}
	probe := ep.probeClient()
	defer probe.CloseIdleConnections()
	row, primary, err := measureGoogle(ctx, probe)
	r.TraceCountry, r.IP = row.Country, row.IP
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	if primary {
		r.AssessmentIP = row.IP
	}
	c := checker{ctx: ctx, client: newClient()}
	defer c.client.CloseIdleConnections()
	risk := c.general(r.IP)
	r.Risk = risk.value
	if risk.err != nil {
		r.RiskDetail = describe(risk.err)
	}
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
		ep, active := p.activeEndpoint(serviceForHost(t.host))
		if !active {
			continue
		}
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
	if ep, active := p.activeEndpoint("Antigravity"); active {
		wg.Add(1)
		go func() { defer wg.Done(); out <- checkGoogle(ctx, ep) }()
	}
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
	r := &serviceRelay{activity: activity}
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
