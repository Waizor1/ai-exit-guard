package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
)

// The root bootstrap owns only the loopback alias and listening socket.
// The process that accepts client data starts with nobody's UID and groups.
func systemIngress(ctx context.Context, mode string) error {
	switch mode {
	case "ingress-worker":
		if os.Geteuid() == 0 {
			return fmt.Errorf("worker cannot run as root")
		}
		file := os.NewFile(3, "AI TLS")
		if file == nil {
			return fmt.Errorf("missing listener")
		}
		ln, err := net.FileListener(file)
		file.Close()
		if err != nil {
			return err
		}
		return serveIngress(ctx, ln, localProxy)
	case "ingress-bootstrap":
		if os.Geteuid() != 0 {
			return fmt.Errorf("bootstrap requires launchd")
		}
		lo, err := net.InterfaceByName("lo0")
		if err != nil {
			return err
		}
		addr, err := lo.Addrs()
		if err != nil {
			return err
		}
		assigned := false
		for _, a := range addr {
			ip, _, _ := net.ParseCIDR(a.String())
			if ip.Equal(net.ParseIP(ingressIP)) {
				assigned = true
			}
		}
		if !assigned {
			if err = exec.CommandContext(ctx, "/sbin/ifconfig", "lo0", "alias", ingressIP, "netmask", "255.255.255.255").Run(); err != nil {
				return err
			}
		}
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(ingressIP), Port: 443})
		if err != nil {
			return err
		}
		defer ln.Close()
		inherited, err := ln.File()
		if err != nil {
			return err
		}
		defer inherited.Close()
		child := exec.CommandContext(ctx, "/Library/PrivilegedHelperTools/local.aiexitguard.ingress", "ingress-worker")
		child.ExtraFiles = []*os.File{inherited}
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{65534}}}
		child.Env = []string{"PATH=/usr/bin:/bin"}
		child.Dir = "/"
		return child.Run()
	}
	return fmt.Errorf("unknown ingress mode")
}
