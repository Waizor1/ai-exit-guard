package main

import (
	"net"
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
