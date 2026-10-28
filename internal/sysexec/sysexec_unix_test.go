//go:build unix

package sysexec

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandIgnoresPATH(t *testing.T) {
	evil := t.TempDir()
	t.Setenv("PATH", evil)
	cmd := Command("sh") // present in /bin on every unix
	if cmd.Err != nil {
		t.Skip("no sh in the system directories: ", cmd.Err)
	}
	if !filepath.IsAbs(cmd.Path) {
		t.Errorf("path %q is not absolute", cmd.Path)
	}
	for _, kv := range cmd.Env {
		if strings.Contains(kv, evil) {
			t.Errorf("user environment leaked: %s", kv)
		}
	}
}

func TestBareNamesOnly(t *testing.T) {
	for _, n := range []string{"", "../bin/sh", "/bin/sh", "a/b"} {
		if cmd := Command(n); cmd.Err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestMissingToolFails(t *testing.T) {
	if err := Command("vpnsplit-no-such-tool").Run(); err == nil {
		t.Error("expected an error")
	}
}
