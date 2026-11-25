// The public listener starts closed. Only its parent's private pipe can renew a lease.
package main

import (
	"context"
	"net"
	"sync"
	"time"
)

type relayGate struct {
	mu     sync.Mutex
	window context.Context
	cancel context.CancelFunc
	expiry time.Time
	timer  *time.Timer
	peers  map[net.Conn]struct{}
}

const maxLease = 180 * time.Second

func (g *relayGate) closeLocked() {
	if g.cancel != nil {
		g.cancel()
		g.cancel = nil
	}
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
	for conn := range g.peers {
		conn.Close()
		delete(g.peers, conn)
	}
	g.window = nil
}

func (g *relayGate) set(until time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if !until.After(now) || until.Sub(now) > maxLease {
		g.closeLocked()
		return false
	}
	if g.window != nil && !g.expiry.IsZero() && !now.Before(g.expiry) {
		g.closeLocked()
	}
	if g.window == nil {
		g.window, g.cancel = context.WithCancel(context.Background())
		g.peers = make(map[net.Conn]struct{})
	}
	g.expiry = until
	if g.timer != nil {
		g.timer.Stop()
	}
	g.timer = time.AfterFunc(time.Until(until), func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if !g.expiry.IsZero() && !time.Now().Before(g.expiry) {
			g.closeLocked()
		}
	})
	return true
}

// Called only by the desktop controller over its private pipe.
func (g *relayGate) proxyOnly() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
	if g.window == nil {
		g.window, g.cancel = context.WithCancel(context.Background())
		g.peers = make(map[net.Conn]struct{})
	}
	g.expiry = time.Time{}
}

func (g *relayGate) current() context.Context {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.expiry.IsZero() && !time.Now().Before(g.expiry) {
		g.closeLocked()
	}
	return g.window
}

func (g *relayGate) attach(window context.Context, conn net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if window == nil || window != g.window || (!g.expiry.IsZero() && !time.Now().Before(g.expiry)) {
		return false
	}
	g.peers[conn] = struct{}{}
	return true
}

func (g *relayGate) remove(conn net.Conn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.peers, conn)
}
