//go:build !darwin

package main

import "context"

func runSystemDNS(context.Context) int { return 1 }
