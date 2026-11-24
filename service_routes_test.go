package main

import (
	"bufio"
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
