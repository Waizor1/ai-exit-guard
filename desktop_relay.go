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
	Expected                   string
	AllowGoogleCountryMismatch bool
	DetailedStatus             bool
}

func (c desktopConfig) pin(service string) string {
	if p, ok := c.Profiles[service]; ok {
		return p.Expected
	}
	return c.Expected
}

// Each Windows status is also the lease decision. Only a successful reading
// has an empty reason; the UI cannot independently relax a closed route.
type desktopRoute struct {
	Until  int64
	Reason string
}

func (c desktopConfig) refusal(r result, countries map[string]string, now time.Time) string {
	reviewed := time.Unix(1795305600, 0)
	service := serviceForHost(r.Host)
	switch {
	case now.Before(reviewed) || !now.Before(reviewed.AddDate(0, 0, 90)):
		return "Обновите Guard: срок проверки списка стран истёк."
	case r.IP == "":
		return "Не удалось проверить выход. Проверьте подключение прокси."
	case r.IP != c.pin(service):
		return "Прокси сменил IP. Проверьте закреплённый адрес."
	case r.Status == "red":
		return "IP123 отметил высокий риск для сервиса."
	case r.IP != r.AssessmentIP:
		return "IP123 не подтвердил закреплённый IP."
	case !valid(r.Risk):
		return "Нет оценки риска для этого IP."
	case *r.Risk > 33:
		return "Риск этого IP выше допустимого."
	case !r.InfoChecked || r.Country == "" || r.TraceCountry == "":
		return "Не удалось подтвердить страну выхода."
	}
	bothSupported := isProtectedCountry(service, r.Country, countries) && isProtectedCountry(service, r.TraceCountry, countries)
	source := "Сервис"
	if service == "Antigravity" {
		source = "Google"
	}
	switch {
	case !bothSupported:
		return fmt.Sprintf("Страна недоступна (%s: %s, IPinfo: %s).", source, r.TraceCountry, r.Country)
	case r.Country != r.TraceCountry && !(service == "Antigravity" && c.AllowGoogleCountryMismatch):
		return fmt.Sprintf("Страны различаются (%s: %s, IPinfo: %s).", source, r.TraceCountry, r.Country)
	case service == "Antigravity" && r.Host == googleHost && r.Status == "google":
		return ""
	case service != "Antigravity" && r.Status == "green" && valid(r.Trust) && *r.Trust > 200.0/3:
		return ""
	default:
		return "Проверка сервиса не подтвердила доступ."
	}
}

func (c desktopConfig) report(output io.Writer, state map[string]desktopRoute) {
	if c.DetailedStatus {
		json.NewEncoder(output).Encode(state)
		return
	}
	// Older Windows clients read only lease deadlines.
	leases := make(map[string]int64, len(state))
	for service, route := range state {
		leases[service] = route.Until
	}
	json.NewEncoder(output).Encode(leases)
}

func refreshDesktop(ctx context.Context, c desktopConfig, relay *serviceRelay, countries map[string]string, state map[string]desktopRoute, output io.Writer) {
	rows := map[string]result{}
	collectPlan(ctx, c.proxyPlan, func(r result) error {
		service := serviceForHost(r.Host)
		rows[r.Host] = r
		// Some checks emit an initial measurement before reputation is available.
		// A changed exit or a red reading must revoke the *previous* lease now.
		reason := c.refusal(r, countries, time.Now())
		// Google emits one complete row. Other probes send preliminary rows
		// before IPinfo returns; missing enrichment alone is not a revocation.
		definitive := service == "Antigravity" || r.InfoChecked || r.InfoDetail != "" || r.IP != c.pin(service) || r.Status == "red" || (valid(r.Risk) && *r.Risk > 33) || (r.AssessmentIP != "" && r.AssessmentIP != r.IP) || (r.TraceCountry != "" && !isProtectedCountry(service, r.TraceCountry, countries))
		if definitive && reason != "" {
			relay.control(service + " 0")
			closed := desktopRoute{Reason: reason}
			if state[service] != closed {
				state[service] = closed
				c.report(output, state)
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
		reason := ""
		for _, host := range group {
			r := rows[host]
			checked, err := time.Parse(time.RFC3339, r.Checked)
			reason = c.refusal(r, countries, now)
			if reason == "" && (err != nil || checked.After(now) || !checked.Add(maxLease).After(now)) {
				reason = "Срок проверки истёк. Ожидаем новый результат."
			}
			if reason != "" {
				until = time.Time{}
				break
			}
			if end := checked.Add(maxLease); end.Before(until) {
				until = end
			}
		}
		state[service] = desktopRoute{Reason: reason}
		if relay.control(fmt.Sprintf("%s %d", service, until.Unix())) == "OPEN" {
			state[service] = desktopRoute{Until: until.Unix()}
		}
	}
	c.report(output, state)
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
	state := map[string]desktopRoute{}
	for ctx.Err() == nil {
		refreshDesktop(ctx, c, relay, countries, state, output)
		select {
		case <-ctx.Done():
		case <-time.After(90 * time.Second):
		}
	}
	return 0
}
