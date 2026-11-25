package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestMCPWorkerWithdrawBeforeReprobe(t *testing.T) {
	now := time.Now()
	host := "mcp.linear.app"
	var out bytes.Buffer
	s := mcpWorkerState{answers: &mcpAnswers{}, encoder: json.NewEncoder(&out), leases: map[string]mcpLease{}}
	s.adopt(&mcpNetwork{})
	deadline := now.Add(2 * time.Second)
	s.leases[host] = mcpLease{[]netip.Addr{netip.MustParseAddr("93.184.216.34")}, deadline, now}
	if err := s.publish(now, true); err != nil {
		t.Fatal(err)
	}
	if got := s.nextDelay(now, false); got != 2*time.Second {
		t.Fatal("late cleanup", got)
	}
	if !s.prune([]string{host}, deadline) {
		t.Fatal("missing cleanup")
	}
	if err := s.publish(deadline, false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "[\"mcp.linear.app\"]\n[]\n" {
		t.Fatal("missing immediate withdrawal", out.String())
	}
	if got := s.nextDelay(deadline, true); got > 10*time.Second {
		t.Fatal("slow recovery", got)
	}
	if len(s.answers.policy.Load().records) != 0 {
		t.Fatal("stale DNS answers after revoke")
	}
}
