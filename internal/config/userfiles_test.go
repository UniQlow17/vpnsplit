package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRegularMax(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadRegularMax(p, 100); err != nil || len(b) != 100 {
		t.Errorf("at the limit: %d %v", len(b), err)
	}
	if _, err := ReadRegularMax(p, 99); err == nil {
		t.Error("over the limit read")
	}
	for _, bad := range []int64{0, -1, maxFileSize + 1} {
		if _, err := ReadRegularMax(p, bad); err == nil {
			t.Errorf("limit %d accepted", bad)
		}
	}
	if _, err := ReadRegularMax(dir, 100); err == nil {
		t.Error("a directory read")
	}
	if _, err := ReadRegularMax(filepath.Join(dir, "missing"), 100); err == nil {
		t.Error("a missing file read")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err == nil {
		if _, err := ReadRegularMax(link, 100); err == nil {
			t.Error("a symlink was followed")
		}
	}
}

func TestRealUserHome(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("PKEXEC_UID", "")
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	got, ok := RealUserHome()
	if !ok || got != h {
		t.Errorf("%q %v", got, ok)
	}
	if _, _, ok := RealUser(); ok {
		t.Error("a user behind sudo without sudo")
	}
}
