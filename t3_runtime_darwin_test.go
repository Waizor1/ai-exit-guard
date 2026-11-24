package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestACPPreflightRequiresCompatibleRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "renamed-client")
	const good = `{"id":1,"result":{"protocolVersion":1,"agentInfo":{"name":"Antigravity ACP Server","version":"9.0"},"agentCapabilities":{"loadSession":true},"authMethods":[{"id":"oauth-personal"}]}}`
	for _, tc := range []struct {
		reply, version string
		ok             bool
	}{
		{good, "9.0", true}, {good, "9.1", false}, {`{"id":1,"error":{"code":-1}}`, "9.0", false},
	} {
		script := "#!/bin/sh\n[ \"$1\" = acp ] || exit 1\nread -r request || exit 2\nprintf '%s\\n' '" + tc.reply + "'\n"
		if err := os.WriteFile(path, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		if err := probeAntigravity(context.Background(), path, tc.version); (err == nil) != tc.ok {
			t.Fatalf("unexpected probe result: %v", err)
		}
	}
}
