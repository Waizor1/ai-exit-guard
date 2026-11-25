package mcpdns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/netip"
	"slices"
	"syscall"
	"testing"
)

func TestEvidenceAndReset(t *testing.T) {
	h := "mcp.figma.com"

	a := netip.MustParseAddr("8.8.4.4")
	b := netip.MustParseAddr("9.9.9.9")
	priv := netip.MustParseAddr("10.1.1.1")
	candidates := []string{"internal.company", h, h}
	var tracker Tracker
	normal, other := []netip.Addr{a}, []netip.Addr{b}
	var fail error = syscall.ECONNREFUSED
	var normalCount, altCount int
	blocked := false
	system := func(_ context.Context, name string) ([]netip.Addr, error) {
		if name != h {
			t.Fatal("uncatalogued host probed")
		}

		normalCount++
		return normal, nil
	}
	alternate := func(_ context.Context, name string) ([]netip.Addr, error) {
		if name != h {
			t.Fatal("invalid external host")
		}
		altCount++
		return other, nil
	}
	tls := func(_ context.Context, name string, ip netip.Addr) error {
		if name != h || !public(ip) {
			t.Fatal("invalid TLS target")
		}
		if ip == a {
			return fail
		}
		return nil
	}
	scan := func(want bool) {
		t.Helper()
		got := tracker.scan(context.Background(), candidates, func(string) bool { return blocked }, system, alternate, tls)
		if (want && !slices.Equal(got[h], []netip.Addr{b})) || (!want && len(got) > 0) {
			t.Fatalf("result %v want eligible=%v", got, want)
		}
	}
	scan(false)
	if altCount != 0 || !tracker.NeedsConfirmation() {
		t.Fatal("alternate contacted on first failure")
	}
	scan(true)
	if normalCount != 2 || altCount != 1 || tracker.NeedsConfirmation() {
		t.Fatal(normalCount, altCount)
	}
	blocked = true
	scan(false)
	if normalCount != 2 {
		t.Fatal("excluded lookup")
	}
	blocked = false
	scan(false)
	scan(true)
	normal = []netip.Addr{priv, a}
	ac := altCount
	scan(false)
	if ac != altCount {
		t.Fatal("local address disclosed")
	}
	normal = []netip.Addr{a}
	fail = x509.UnknownAuthorityError{}
	scan(false)
	if ac != altCount {
		t.Fatal("certificate failure misclassified")
	}
	fail = nil
	scan(false)
	fail = syscall.ECONNRESET
	other = []netip.Addr{b, priv}
	scan(false)
	other = []netip.Addr{a}
	scan(false)
	other = []netip.Addr{b}
	scan(false)
	scan(true)

	candidates = nil
	scan(false)
	candidates = []string{h}
	scan(false)
}
func TestNonPublicRanges(t *testing.T) {
	for _, raw := range []string{"10.0.0.1", "::1", "ff00::", "192.168.0.1", "169.254.0.1", "100.64.0.1", "198.18.0.0", "203.0.113.4", "2001:db8::1", "64:ff9b::808:808", "::ffff:127.0.0.1", "2002::1", "3fff::1", "fc00::12", "250.1.1.1"} {
		if public(netip.MustParseAddr(raw)) {
			t.Error(raw)
		}
	}
	if transportFailure(&tls.CertificateVerificationError{Err: context.DeadlineExceeded}) {
		t.Fatal("certificate error counted as transport timeout")
	}
	if transportFailure(errors.New("TLS alert")) {
		t.Error("counted TLS protocol error")
	}
}

func TestOnlyExplicitNativeDNSFailuresQualify(t *testing.T) {
	h := "mcp.linear.app"
	c := []string{h}
	var tracker Tracker
	var nativeErr error = ErrNoDNSAnswer
	var normal []netip.Addr
	system := func(context.Context, string) ([]netip.Addr, error) { return normal, nativeErr }
	calls := 0
	alternate := func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
	}
	scan := func() map[string][]netip.Addr {
		return tracker.scan(context.Background(), c, func(string) bool { return false }, system, alternate, func(context.Context, string, netip.Addr) error { return nil })
	}
	if len(scan()) != 0 || calls != 0 {
		t.Fatal("disclosed first failure")
	}
	if len(scan()) != 1 || calls != 1 {
		t.Fatal("missing second failure evidence")
	}
	nativeErr = errors.New("command failed")
	scan()
	scan()
	normal = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	nativeErr = ErrNoDNSAnswer
	scan()
	scan()
	normal = nil
	nativeErr = nil
	scan()
	scan()
	if calls != 1 {
		t.Fatal("disclosed after ambiguous evidence")
	}
}

func TestBatchBoundAndRotation(t *testing.T) {
	candidates := make([]string, 0, 26)
	for h := range catalog {
		candidates = append(candidates, h)
		if len(candidates) == 25 {
			break
		}
	}
	candidates = append(candidates, "private.internal")
	var tracker Tracker
	seen := map[string]bool{}
	for range 3 {
		a, b := tracker.batch(candidates), tracker.batch(candidates)
		if len(a) != 10 || !slices.Equal(a, b) {
			t.Fatal(a, b)
		}
		for _, h := range a {
			if catalog[h] == "" {
				t.Fatal(h)
			}
			seen[h] = true
		}
	}
	if len(seen) != 25 {
		t.Fatal("starved", len(seen))
	}
}
