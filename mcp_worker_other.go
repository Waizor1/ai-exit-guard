//go:build !darwin

package main

import "context"

func runMCPDNS(_ context.Context) int { return 1 }
