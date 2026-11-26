package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// syntheticPE builds a minimal PE image with one executable section that holds
// the manager gate at sectionOffset.
func syntheticPE(gate []byte, sectionOffset int) []byte {
	const lfanew = 0x80
	const rawPtr = 0x400
	const rawSize = 0x400
	data := make([]byte, rawPtr+rawSize)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], lfanew)
	copy(data[lfanew:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[lfanew+6:], 1)     // sections
	binary.LittleEndian.PutUint16(data[lfanew+20:], 0xE0) // optional header size
	header := lfanew + 24 + 0xE0
	copy(data[header:], ".text")
	binary.LittleEndian.PutUint32(data[header+16:], rawSize)
	binary.LittleEndian.PutUint32(data[header+20:], rawPtr)
	binary.LittleEndian.PutUint32(data[header+36:], 0x20000000|0x40000000)
	copy(data[rawPtr+sectionOffset:], gate)
	return data
}

func TestPEGateState(t *testing.T) {
	plain, _ := parseGatePattern("80 78 08 00 74 2a 48 8b 54 24 70 48 89 50 60")
	patched, _ := parseGatePattern("c6 40 08 01 90 90 48 8b 54 24 70 48 89 50 60")

	state, offset, err := peGateState(syntheticPE(plain, 0x40))
	if err != nil || state != "unpatched" || offset != 0x440 {
		t.Fatalf("plain: state=%q offset=%#x err=%v", state, offset, err)
	}
	state, _, err = peGateState(syntheticPE(patched, 0x40))
	if err != nil || state != "patched" {
		t.Fatalf("patched: state=%q err=%v", state, err)
	}
	state, _, err = peGateState(syntheticPE([]byte("nothing here"), 0x40))
	if state != "unsupported" || err == nil {
		t.Fatalf("missing gate: state=%q err=%v", state, err)
	}
}

func TestPEPatchRestore(t *testing.T) {
	plain, _ := parseGatePattern("80 78 08 00 74 2a 48 8b 54 24 70 48 89 50 60")
	dir := t.TempDir()
	exe := filepath.Join(dir, "language_server.exe")
	if err := os.WriteFile(exe, syntheticPE(plain, 0x40), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AI_GUARD_ANTIGRAVITY_APP", exe)

	if report := antigravityPERun("status"); report.State != "unpatched" {
		t.Fatalf("initial status = %q", report.State)
	}
	if report := antigravityPERun("patch"); report.State != "patched" || report.Rc != 0 {
		t.Fatalf("patch = %q rc=%d %s", report.State, report.Rc, report.Detail)
	}
	if _, err := os.Stat(exe + ".agybak"); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if report := antigravityPERun("status"); report.State != "patched" {
		t.Fatalf("status after patch = %q", report.State)
	}
	if report := antigravityPERun("restore"); report.State != "unpatched" || report.Rc != 0 {
		t.Fatalf("restore = %q rc=%d %s", report.State, report.Rc, report.Detail)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if state, _, _ := peGateState(data); state != "unpatched" {
		t.Fatalf("file after restore = %q", state)
	}
}

// TestPEGateRealBinary checks the shipped signature against a real Windows
// build. Set AI_GUARD_PE_FIXTURE to language_server.exe to run it.
func TestPEGateRealBinary(t *testing.T) {
	fixture := os.Getenv("AI_GUARD_PE_FIXTURE")
	if fixture == "" {
		t.Skip("AI_GUARD_PE_FIXTURE not set")
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	state, offset, err := peGateState(data)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	t.Logf("state=%s offset=%#x", state, offset)
	if state != "unpatched" && state != "patched" {
		t.Fatalf("unexpected state %q", state)
	}
}

// TestPERealBinaryPatch runs patch and restore against a copy of a real build.
func TestPERealBinaryPatch(t *testing.T) {
	fixture := os.Getenv("AI_GUARD_PE_FIXTURE")
	if fixture == "" {
		t.Skip("AI_GUARD_PE_FIXTURE not set")
	}
	original, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "language_server.exe")
	if err := os.WriteFile(exe, original, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AI_GUARD_ANTIGRAVITY_APP", exe)
	if report := antigravityPERun("patch"); report.State != "patched" || report.Rc != 0 {
		t.Fatalf("patch = %q rc=%d %s", report.State, report.Rc, report.Detail)
	}
	if report := antigravityPERun("restore"); report.State != "unpatched" || report.Rc != 0 {
		t.Fatalf("restore = %q rc=%d %s", report.State, report.Rc, report.Detail)
	}
	restored, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatal("restored file differs from the original build")
	}
}
