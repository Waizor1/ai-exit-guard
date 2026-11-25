package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type profileRequest struct {
	Endpoint          proxySpec
	Service, Expected string
}
type profileMeasurement struct{ IP, Country string }
type profileResult struct {
	profileMeasurement
	Status string
}

func measureProfile(ctx context.Context, ep proxySpec, client *http.Client, host string) profileMeasurement {
	if host == googleHost {
		// Google reports its region on the public sign-in page. Its page does
		// not echo an IP, so ask IP123 via exactly the same upstream proxy.
		country := make(chan string, 1)
		go func() {
			v, _ := retryNetworkOnce(ctx, func() (string, error) { return googleRegion(ctx, ep) })
			country <- v
		}()
		var who struct{ IP string }
		body, err := probeBody(ctx, client, api+"/ip.json")
		if err == nil {
			_ = json.Unmarshal(body, &who)
		}
		ip, _ := canonical(who.IP)
		return profileMeasurement{ip, <-country}
	}
	body, err := probeBody(ctx, client, "https://"+host+"/cdn-cgi/trace")
	if err != nil {
		return profileMeasurement{}
	}
	ip, country, err := traceExit(body, host)
	if err != nil {
		return profileMeasurement{}
	}
	return profileMeasurement{ip, country}
}

func summarizeProfile(rows []profileMeasurement, expected string) profileResult {
	report := profileResult{Status: "unavailable"}
	for i, row := range rows {
		if row.IP == "" || len(row.Country) != 2 || row.Country[0] < 'A' || row.Country[0] > 'Z' || row.Country[1] < 'A' || row.Country[1] > 'Z' || row.Country == "XX" {
			return profileResult{Status: "unavailable"}
		}
		if i > 0 && report.profileMeasurement != row {
			return profileResult{Status: "inconsistent"}
		}
		report.profileMeasurement = row
	}
	if len(rows) > 0 {
		report.Status = "ok"
		if expected != "" && report.IP != expected {
			report.Status = "changed"
		}
	}
	return report
}

func profileCheckCommand(parent context.Context, input io.Reader, output io.Writer) int {
	const limit = 8192
	data, err := io.ReadAll(io.LimitReader(input, limit+1))
	var req profileRequest
	if err != nil || len(data) > limit || json.Unmarshal(data, &req) != nil || !req.Endpoint.valid() {
		return 2
	}
	if req.Expected != "" {
		req.Expected, err = canonical(req.Expected)
		if err != nil {
			return 2
		}
	}
	var hosts []string
	if req.Service == "Antigravity" {
		hosts = []string{googleHost}
	} else {
		for _, t := range targets {
			if req.Service == "" || req.Service == serviceForHost(t.host) {
				hosts = append(hosts, t.host)
			}
		}
	}
	if len(hosts) == 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	probe := req.Endpoint.probeClient()
	defer probe.CloseIdleConnections()
	out := make(chan profileMeasurement, len(hosts))
	for _, h := range hosts {
		go func() { out <- measureProfile(ctx, req.Endpoint, probe, h) }()
	}
	rows := make([]profileMeasurement, 0, len(hosts))
	for range hosts {
		select {
		case v := <-out:
			rows = append(rows, v)
		case <-ctx.Done():
			rows = append(rows, profileMeasurement{})
		}
	}
	if json.NewEncoder(output).Encode(summarizeProfile(rows, req.Expected)) != nil {
		return 1
	}
	return 0
}
