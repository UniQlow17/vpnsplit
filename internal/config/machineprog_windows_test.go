//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDosFinalPath(t *testing.T) {
	ok := map[string]string{
		`\\?\C:\Program Files\vpnsplit\vpnsplit.exe`: `C:\Program Files\vpnsplit\vpnsplit.exe`,
		`C:\plain\path`: `C:\plain\path`,
	}
	for in, want := range ok {
		got, err := dosFinalPath(in)
		if err != nil || got != want {
			t.Errorf("dosFinalPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{`\\?\UNC\server\share\a.exe`, `\\?\unc\server\share\a.exe`} {
		if _, err := dosFinalPath(in); err == nil {
			t.Errorf("dosFinalPath(%q): a network share must be refused", in)
		}
	}
}

// A real file in a temporary directory: the system's answer (`\?\C:\...`)
// must match the path asked. Nothing is written outside the temporary directory.
func TestVerifyFinalPathPlainFile(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Skip(err)
	}
	f := filepath.Join(dir, "a.exe")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFinalPath(f); err != nil {
		t.Errorf("verifyFinalPath(%s): %v", f, err)
	}
}
