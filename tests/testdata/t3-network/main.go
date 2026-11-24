// Fixed-function diagnostic. No agent, account, credential or model endpoint is used.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"time"
)

const target = "https://github.com/robots.txt"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// A named probe attempts ordinary TLS itself, then performs the same check
	// in a different executable. This distinguishes a process filter from an
	// inherited block on every tool. No request contains credentials.
	client := http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Head(target)
	direct := err == nil
	if direct {
		res.Body.Close()
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/curl", "-q", "--proxy", "", "--max-time", "7", "--silent", "--output", "/dev/null", "--head", target)
	child := cmd.Run() == nil
	sshOK := false
	if len(os.Args) == 2 && os.Args[1] != "" {
		ssh := exec.CommandContext(ctx, "/usr/bin/ssh", "-T", "-n", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5", "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "--", os.Args[1], "true")
		sshOK = ssh.Run() == nil
	}
	json.NewEncoder(os.Stdout).Encode(struct{ Direct, Child, SSH bool }{direct, child, sshOK})
}
