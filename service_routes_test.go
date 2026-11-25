package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestServiceTunnelsAndLeases(t *testing.T) {
	upstream := func(label string) (proxySpec, func()) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, b, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer c.Close()
			fmt.Fprint(b, "HTTP/1.1 200 OK\r\n\r\n")
			b.Flush()
			for {
				s, e := b.ReadString('\n')
				if e != nil {
					return
				}
				if s == "identity\n" {
					s = label + "\n"
				}
				fmt.Fprint(b, s)
				b.Flush()
			}
		}))
		h, p, _ := net.SplitHostPort(server.Listener.Addr().String())
		n, _ := strconv.Atoi(p)
		return proxySpec{Scheme: "http", Host: h, Port: n}, server.Close
	}
	common, done := upstream("common")
	defer done()
	other, done := upstream("individual")
	defer done()
	p := proxyPlan{Common: common, Profiles: map[string]individualProxy{"Antigravity": {Endpoint: other, Expected: "1.1.1.1"}}}
	relay := &serviceRelay{}
	relay.configure(p)
	defer relay.close()
	local := httptest.NewServer(relay)
	defer local.Close()
	open := func(host string, expect int, wantRoute string) (net.Conn, *bufio.Reader) {
		t.Helper()
		c, e := net.DialTimeout("tcp", local.Listener.Addr().String(), 2*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		rd := bufio.NewReader(c)
		fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
		resp, e := http.ReadResponse(rd, &http.Request{Method: "CONNECT"})
		if e != nil || resp.StatusCode != expect {
			c.Close()
			t.Fatalf("%s: expected %d, got %v %v", host, expect, resp, e)
		}
		if expect != 200 {
			c.Close()
			return nil, nil
		}
		fmt.Fprintln(c, "identity")
		line, e := rd.ReadString('\n')
		if e != nil || strings.TrimSpace(line) != wantRoute {
			c.Close()
			t.Fatalf("%s went to wrong upstream", host)
		}
		return c, rd
	}
	deadline := strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10)
	// Exercise the same live TCP relay and authenticated profile transaction used by the app.
	applyPause := func(paused bool) {
		t.Helper()
		p.CommonPaused = paused
		raw, err := json.Marshal(p)
		if err != nil || relay.control("config "+string(raw)) != "READY" {
			t.Fatal("common pause transaction failed")
		}
	}
	for _, mode := range []string{"mode guarded", "mode proxy-only"} {
		relay.control(mode)
		for _, name := range services {
			relay.control(name + " " + deadline)
		}
		shared, sr := open("api.openai.com", 200, "common")
		individual, ir := open("accounts.google.com", 200, "individual")
		applyPause(true)
		if _, err := sr.ReadByte(); err == nil {
			t.Fatal("paused common stream remained open")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("paused stream timed out instead of closing")
		}
		shared.Close()
		if relay.control("ChatGPT "+deadline) != "CLOSED" {
			t.Fatal("diagnostic could open paused common route")
		}
		open("api.openai.com", 503, "")
		open("claude.ai", 503, "")
		fmt.Fprintln(individual, "survived-pause")
		if line, err := ir.ReadString('\n'); err != nil || line != "survived-pause\n" {
			t.Fatal("individual stream interrupted by common pause")
		}
		applyPause(false)
		if mode == "mode guarded" {
			open("api.openai.com", 503, "")
			relay.control("ChatGPT " + deadline)
		}
		restored, _ := open("api.openai.com", 200, "common")
		restored.Close()
		fmt.Fprintln(individual, "survived-resume")
		if line, err := ir.ReadString('\n'); err != nil || line != "survived-resume\n" {
			t.Fatal("individual stream interrupted by common resume")
		}
		individual.Close()
	}
	relay.control("mode guarded")
	for _, name := range services {
		if relay.control(name+" "+deadline) != "OPEN" {
			t.Fatal(name)
		}
	}
	claude, cr := open("api.anthropic.com", 200, "common")
	defer claude.Close()
	chat, _ := open("chatgpt.com", 200, "common")
	defer chat.Close()
	g, gr := open("daily-cloudcode-pa.googleapis.com", 200, "individual")
	defer g.Close()
	auth, _ := open("www.googleapis.com", 200, "individual")
	defer auth.Close()
	if relay.control("Antigravity 0") != "CLOSED" {
		t.Fatal("red")
	}
	if _, e := gr.ReadByte(); e == nil {
		t.Fatal("old red tunnel remained open")
	} else if n, ok := e.(net.Error); ok && n.Timeout() {
		t.Fatal("red tunnel timed out instead of closing")
	}
	open("accounts.google.com", 503, "")
	fmt.Fprintln(claude, "still alive")
	if s, e := cr.ReadString('\n'); e != nil || s != "still alive\n" {
		t.Fatal("unrelated Claude connection interrupted")
	}
	p.Profiles = map[string]individualProxy{"ChatGPT": {Endpoint: other, Expected: "8.8.8.8"}}
	raw, _ := json.Marshal(p)
	if relay.control("config "+string(raw)) != "READY" {
		t.Fatal("reconfiguration failed")
	}
	open("api.openai.com", 503, "")
	open("accounts.google.com", 503, "")
	for _, name := range []string{"Antigravity", "ChatGPT"} {
		relay.control(name + " " + deadline)
	}
	g2, _ := open("aicode.googleapis.com", 200, "common")
	g2.Close()
	c2, _ := open("api.openai.com", 200, "individual")
	c2.Close()
	// A failed individual upstream must never use the reachable common endpoint.
	unavailable, stop := upstream("unreachable")
	stop()
	p.Profiles["Claude"] = individualProxy{Endpoint: unavailable, Expected: "1.1.1.1"}
	raw, _ = json.Marshal(p)
	if relay.control("config "+string(raw)) != "READY" {
		t.Fatal("could not apply unavailable route")
	}
	relay.control("Claude " + deadline)
	open("api.anthropic.com", 502, "")
	unaffected, _ := open("api.openai.com", 200, "individual")
	unaffected.Close()

	open("drive.google.com", 403, "")
}

func TestDiagnosticsSkipPausedCommon(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // No external test connections, even on a regression.
	p := proxyPlan{CommonPaused: true}
	if code := collectPlan(ctx, p, func(r result) error { t.Errorf("probe emitted a result for paused %s", r.Host); return nil }); code != 0 {
		t.Fatal(code)
	}
	p.Profiles = map[string]individualProxy{"Antigravity": {Endpoint: proxySpec{Scheme: "http", Host: "127.0.0.1", Port: 1}, Expected: "192.0.2.1"}}
	var rows []string
	collectPlan(ctx, p, func(r result) error { rows = append(rows, r.Host); return nil })
	if len(rows) != 1 || rows[0] != googleHost {
		t.Fatalf("expected only the active individual route, got %v", rows)
	}
}
