package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"time"
)

//go:embed windows/regions.json
var regionData []byte

type desktopConfig struct {
	proxyPlan
	Expected string
}

func (c desktopConfig) pin(service string) string {
	if p, ok := c.Profiles[service]; ok {
		return p.Expected
	}
	return c.Expected
}

func acceptedReading(r result, pin string, countries map[string]string, now time.Time) bool {
	reviewed := time.Unix(1795305600, 0)
	if now.Before(reviewed) || !now.Before(reviewed.AddDate(0, 0, 90)) {
		return false
	}
	service := serviceForHost(r.Host)
	if r.IP == "" || r.IP != pin || r.IP != r.AssessmentIP || !r.InfoChecked || !valid(r.Risk) || *r.Risk > 33 || r.TraceCountry != r.Country || !isProtectedCountry(service, r.Country, countries) {
		return false
	}
	if service == "Antigravity" {
		return r.Status == "google"
	}
	return r.Status == "green" && valid(r.Trust) && *r.Trust > 200.0/3
}

func refreshDesktop(ctx context.Context, c desktopConfig, relay *serviceRelay, countries map[string]string, state map[string]int64, output io.Writer) {
	rows := map[string]result{}
	collectPlan(ctx, c.proxyPlan, func(r result) error {
		service := serviceForHost(r.Host)
		rows[r.Host] = r
		// Some checks emit an initial measurement before reputation is available.
		// A changed exit or a red reading must revoke the *previous* lease now.
		if r.IP != c.pin(service) || r.Status == "red" || (r.Risk != nil && *r.Risk > 66) || (r.TraceCountry != "" && !isProtectedCountry(service, r.TraceCountry, countries)) {
			relay.control(service + " 0")
			if state[service] != 0 {
				state[service] = 0
				json.NewEncoder(output).Encode(state)
			}
		}
		return nil
	})

	for _, service := range services {
		var group []string
		if service == "Antigravity" {
			group = []string{googleHost}
		} else {
			for _, t := range targets {
				if serviceForHost(t.host) == service {
					group = append(group, t.host)
				}
			}
		}
		now := time.Now()
		until := now.Add(maxLease)
		for _, host := range group {
			r := rows[host]
			checked, err := time.Parse(time.RFC3339, r.Checked)
			if err != nil || checked.After(now) || !acceptedReading(r, c.pin(service), countries, now) {
				until = time.Time{}
				break
			}
			if end := checked.Add(maxLease); end.Before(until) {
				until = end
			}
		}
		state[service] = 0
		if relay.control(fmt.Sprintf("%s %d", service, until.Unix())) == "OPEN" {
			state[service] = until.Unix()
		}
	}
	json.NewEncoder(output).Encode(state)
}

func desktopRelay(parent context.Context, input io.Reader, output io.Writer) int {
	sc := bufio.NewScanner(input)
	var c desktopConfig
	if !sc.Scan() || json.Unmarshal(bytes.TrimPrefix(sc.Bytes(), []byte{0xef, 0xbb, 0xbf}), &c) != nil || !c.valid() {
		return 2
	}
	if _, err := canonical(c.Expected); err != nil {
		return 2
	}
	var countries map[string]string
	if json.Unmarshal(regionData, &countries) != nil {
		return 2
	}
	ln, err := net.Listen("tcp4", localProxy)
	if err != nil {
		return 1
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if runtime.GOOS == "windows" {
		local, err := net.Listen("tcp4", net.JoinHostPort(ingressIP, "443"))
		if err != nil {
			ln.Close()
			return 3
		}
		go func() { defer cancel(); _ = serveIngress(ctx, local, localProxy) }()
	}
	relay := &serviceRelay{}
	relay.configure(c.proxyPlan)
	defer relay.close()
	srv := &http.Server{Handler: relay, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 32768}
	go func() { defer cancel(); _ = srv.Serve(ln) }()
	defer srv.Close()
	go func() {
		for sc.Scan() {
		}
		cancel()
	}()
	fmt.Fprintln(output, "READY")
	state := map[string]int64{}
	for ctx.Err() == nil {
		refreshDesktop(ctx, c, relay, countries, state, output)
		select {
		case <-ctx.Done():
		case <-time.After(90 * time.Second):
		}
	}
	return 0
}
