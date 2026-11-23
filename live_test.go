package main

import (
	"context"
	"os"
	"testing"
)

func TestLiveLookup(t *testing.T) {
	if os.Getenv("AI_GUARD_LIVE") != "1" {
		t.Skip("optional live IP123 check")
	}
	c := checker{ctx: context.Background(), client: newClient()}
	defer c.client.CloseIdleConnections()
	x := c.general("1.1.1.1")
	if x.err != nil {
		t.Fatal(x.err)
	}
	t.Log("public control address validated, risk", *x.value)
}
