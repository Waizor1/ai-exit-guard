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

func measureProfile(ctx context.Context, client *http.Client, host string) profileMeasurement {
	if host == googleHost {
		row, _, _ := measureGoogle(ctx, client)
		return row
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
			if len(rows) == 1 {
				report.profileMeasurement = row
				if row.IP != "" && expected != "" && row.IP != expected {
					report.Status = "changed"
				}
				return report
			}
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
	timeout := 15 * time.Second
	if req.Service == "Antigravity" {
		timeout = googleMeasurementTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	probe := req.Endpoint.probeClient()
	defer probe.CloseIdleConnections()
	out := make(chan profileMeasurement, len(hosts))
	for _, h := range hosts {
		go func() { out <- measureProfile(ctx, probe, h) }()
	}
	rows := make([]profileMeasurement, 0, len(hosts))
	for range hosts {
		rows = append(rows, <-out)
	}
	if json.NewEncoder(output).Encode(summarizeProfile(rows, req.Expected)) != nil {
		return 1
	}
	return 0
}
