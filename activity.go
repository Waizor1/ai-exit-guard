// Live TCP attribution. Inspect socket metadata only; never read traffic or command arguments.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type liveFlows struct {
	sync.Mutex
	peers        map[string]string
	recent       []flowEvent
	recordEvents bool
}

func (f *liveFlows) track(peer, host string) func() {
	if f == nil || !aiHost(host) {
		return func() {}
	}
	f.Lock()
	f.peers[peer] = host
	f.Unlock()
	return func() { f.Lock(); delete(f.peers, peer); f.Unlock() }
}

type flowEvent struct {
	Domain string
	Status string
	At     int64
}

func (f *liveFlows) record(host, status string) {
	if f == nil || !f.recordEvents || !aiHost(host) {
		return
	}
	f.Lock()
	defer f.Unlock()
	if len(f.recent) == 64 {
		copy(f.recent, f.recent[1:])
		f.recent = f.recent[:63]
	}
	f.recent = append(f.recent, flowEvent{host, status, time.Now().Unix()})
}

func (f *liveFlows) desktopSnapshot() []flowEvent {
	f.Lock()
	defer f.Unlock()
	rows := make([]flowEvent, 0, len(f.peers)+len(f.recent))
	for _, host := range f.peers {
		rows = append(rows, flowEvent{Domain: host, Status: "active"})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Domain < rows[j].Domain })
	for i := len(f.recent) - 1; i >= 0; i-- {
		rows = append(rows, f.recent[i])
	}
	return rows
}

func (f *liveFlows) snapshot() map[string]string {
	f.Lock()
	defer f.Unlock()
	m := make(map[string]string, len(f.peers))
	for p, h := range f.peers {
		m[p] = h
	}
	return m
}

// The parent creates a private directory for this particular relay before passing the socket path.
func (f *liveFlows) publish(path string) (net.Listener, error) {
	ln, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.SetWriteDeadline(time.Now().Add(time.Second))
			_ = json.NewEncoder(c).Encode(f.snapshot())
			c.Close()
		}
	}()
	return ln, nil
}
func readFlows(path string) map[string]string {
	if path == "" {
		return nil
	}
	c, e := net.DialTimeout("unix", path, time.Second)
	if e != nil {
		return nil
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	var m map[string]string
	if json.NewDecoder(io.LimitReader(c, 2<<20)).Decode(&m) != nil {
		return nil
	}
	return m
}

type processInfo struct {
	parent int
	path   string
}

func processTable(raw string) map[int]processInfo {
	out := map[int]processInfo{}
	for _, line := range strings.Split(raw, "\n") {
		l := strings.TrimSpace(line)
		pidText, rest, ok := strings.Cut(l, " ")
		if !ok {
			continue
		}
		parentText, path, ok := strings.Cut(strings.TrimSpace(rest), " ")
		if !ok {
			continue
		}
		pid, e := strconv.Atoi(pidText)
		parent, e2 := strconv.Atoi(parentText)
		if e == nil && e2 == nil {
			out[pid] = processInfo{parent, strings.TrimSpace(path)}
		}
	}
	return out
}
func appName(pid int, table map[int]processInfo) string {
	leaf := filepath.Base(table[pid].path)
	for n := 0; n < 48 && pid > 1; n++ {
		p, ok := table[pid]
		if !ok {
			break
		}
		if app, _, ok := strings.Cut(p.path, ".app/"); ok {
			name := filepath.Base(app)
			if (leaf == "codex" || leaf == "claude") && !strings.EqualFold(leaf, name) {
				return name + " · " + leaf
			}
			return name
		}
		pid = p.parent
	}
	if leaf == "." || leaf == "" {
		return "Процесс macOS"
	}
	return leaf
}

type activityRow struct {
	App, Domain, Route string
	Count              int
}
type activityReport struct {
	Rows          []activityRow
	Registry, DNS bool
}

func attribute(raw string, table map[int]processInfo, peers map[string]string, addresses map[netip.Addr][]string) []activityRow {
	type key struct{ app, domain, route string }
	counts := map[key]int{}
	pid := 0
	for _, line := range strings.Split(raw, "\n") {
		if len(line) < 2 {
			continue
		}
		if line[0] == 'p' {
			pid, _ = strconv.Atoi(line[1:])
			continue
		}
		if line[0] != 'n' || pid == 0 {
			continue
		}
		src, dst, ok := strings.Cut(line[1:], "->")
		if !ok {
			continue
		}
		var domain, route string
		if dst == localProxy {
			if domain = peers[src]; domain != "" {
				route = "guard"
			} else {
				route = "listener"
			}
		} else {
			dstAddr, e := netip.ParseAddrPort(dst)
			if e != nil || dstAddr.Port() != 443 {
				continue
			}
			names := addresses[dstAddr.Addr().Unmap()]
			if len(names) == 0 {
				continue
			}
			domain = strings.Join(names, ", ")
			route = "outside"
		}
		counts[key{appName(pid, table), domain, route}]++
	}
	rows := make([]activityRow, 0, len(counts))
	for k, n := range counts {
		rows = append(rows, activityRow{k.app, k.domain, k.route, n})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.App != b.App {
			return a.App < b.App
		}
		if a.Route != b.Route {
			return a.Route > b.Route
		}
		return a.Domain < b.Domain
	})
	return rows
}
func activityCommand(parent context.Context, path string) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	ips := map[netip.Addr][]string{}
	complete := true
	type lookup struct {
		h   string
		ips []netip.Addr
		err error
	}
	ch := make(chan lookup, len(targets))
	dns, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer stop()
	for _, t := range targets {
		go func(h string) { v, e := net.DefaultResolver.LookupNetIP(dns, "ip", h); ch <- lookup{h, v, e} }(t.host)
	}
	for range targets {
		v := <-ch
		if v.err != nil || len(v.ips) == 0 {
			complete = false
		}
		for _, ip := range v.ips {
			k := ip.Unmap()
			ips[k] = append(ips[k], v.h)
		}
	}
	for ip := range ips {
		sort.Strings(ips[ip])
	}
	before := readFlows(path)
	sockets, e := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-a", "-u", strconv.Itoa(os.Getuid()), "-iTCP", "-sTCP:ESTABLISHED", "-Fpn").Output()
	var exit *exec.ExitError
	if e != nil && !(errors.As(e, &exit) && exit.ExitCode() == 1 && len(sockets) == 0 && len(exit.Stderr) == 0) {
		return fmt.Errorf("socket inventory unavailable")
	}
	after := readFlows(path)
	stable := map[string]string{}
	for peer, domain := range before {
		if after[peer] == domain {
			stable[peer] = domain
		}
	}
	ps, e := exec.CommandContext(ctx, "/bin/ps", "-axo", "pid=,ppid=,comm=").Output()
	if e != nil {
		return fmt.Errorf("process inventory unavailable")
	}
	return json.NewEncoder(os.Stdout).Encode(activityReport{attribute(string(sockets), processTable(string(ps)), stable, ips), before != nil && after != nil, complete})
}
