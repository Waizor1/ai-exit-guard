package main

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLeaseRevocationAndExpiry(t *testing.T) {
	gate := &relayGate{}
	if gate.current() != nil {
		t.Fatal("startup open")
	}
	if !gate.set(time.Now().Add(time.Minute)) {
		t.Fatal("lease rejected")
	}
	pending := gate.current()
	gate.set(time.Time{})
	if !gate.set(time.Now().Add(time.Minute)) {
		t.Fatal("recovery failed")
	}
	peer, other := net.Pipe()
	defer other.Close()
	defer peer.Close()
	if gate.attach(pending, peer) {
		t.Fatal("connection from revoked window admitted after reopen")
	}
	live := gate.current()
	if !gate.attach(live, peer) {
		t.Fatal("fresh window rejected")
	}
	gate.set(time.Now().Add(80 * time.Millisecond))
	select {
	case <-live.Done():
	case <-time.After(time.Second):
		t.Fatal("stale assessment retained")
	}
	other.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := other.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired connection survived")
	}
	if gate.current() != nil || gate.set(time.Now().Add(10*time.Minute)) {
		t.Fatal("invalid lease accepted")
	}
}

func TestProxyOnlyMode(t *testing.T) {
	relay := serviceRelay{}
	relay.configure(proxyPlan{})
	spec := relay.routes["Claude"]
	if spec.gate.current() != nil {
		t.Fatal("open by default")
	}
	if relay.control("mode proxy-only") != "READY" {
		t.Fatal("mode refused")
	}
	ctx := spec.gate.current()
	client, peer := net.Pipe()
	defer peer.Close()
	if !spec.gate.attach(ctx, client) {
		t.Fatal("proxy-only session rejected")
	}
	relay.configure(proxyPlan{})
	if spec.gate.current() != ctx {
		t.Fatal("unchanged route lost")
	}
	relay.control("mode guarded")
	if spec.gate.current() != nil || ctx.Err() == nil {
		t.Fatal("re-enabling protection retained open stream")
	}
}

func TestProxyOnlyProfile(t *testing.T) {
	var b bytes.Buffer
	if err := writeRoutingProfile(&b, "darwin", true); err != nil {
		t.Fatal(err)
	}
	var profile struct {
		ProxyRules []struct{ Action, TargetHosts, TargetPorts string }
	}
	if json.Unmarshal(b.Bytes(), &profile) != nil || len(profile.ProxyRules) == 0 {
		t.Fatal("no routes")
	}
	for _, rule := range profile.ProxyRules {
		if rule.Action != "guard" || rule.TargetPorts != "443" || !aiHost(strings.TrimPrefix(rule.TargetHosts, "*.")) {
			t.Fatal(rule)
		}
	}
}
