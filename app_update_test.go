package main

import "testing"

func TestCompareAppVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.14.14", "1.14.14", 0},
		{"v1.14.14", "1.14.14", 0},
		{"1.14.14-beta", "1.14.14", -1},
		{"1.14.14", "1.14.14-beta", 1},
		{"1.14.14-beta", "1.15.0-beta", -1},
		{"1.15.0", "1.14.14", 1},
		{"1.15.1", "1.15.0", 1},
	}
	for _, c := range cases {
		if got := compareAppVersions(c.a, c.b); got != c.want {
			t.Errorf("compareAppVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSelectReleaseAsset(t *testing.T) {
	assets := []githubAsset{
		{Name: "AI-Exit-Guard-1.15.0.dmg", BrowserDownloadURL: "https://example.test/mac.dmg"},
		{Name: "AI-Exit-Guard-Windows-x64.zip", BrowserDownloadURL: "https://example.test/win.zip"},
		{Name: "SHA256SUMS.txt", BrowserDownloadURL: "https://example.test/SHA256SUMS.txt"},
	}
	mac, sums, ok := selectReleaseAsset(assets, "darwin")
	if !ok || mac.Name != "AI-Exit-Guard-1.15.0.dmg" || sums == "" {
		t.Fatalf("darwin selection failed: %+v sums=%q ok=%v", mac, sums, ok)
	}
	win, sums, ok := selectReleaseAsset(assets, "windows")
	if !ok || win.Name != "AI-Exit-Guard-Windows-x64.zip" || sums == "" {
		t.Fatalf("windows selection failed: %+v sums=%q ok=%v", win, sums, ok)
	}
}

func TestParseSHA256Sums(t *testing.T) {
	body := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  AI-Exit-Guard-1.15.0.dmg\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *AI-Exit-Guard-Windows-x64.zip\n"
	if got := parseSHA256Sums(body, "AI-Exit-Guard-Windows-x64.zip"); got != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("got %q", got)
	}
}
