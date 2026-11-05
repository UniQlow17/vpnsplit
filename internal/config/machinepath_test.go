package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A program in a directory a user can write is refused, with the reason.
func TestProtectedExeRefusesUserDirectory(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "vpnsplit")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ProtectedExe(exe); err == nil {
		t.Fatal("a program in a temporary directory must not pass")
	}
}

func TestProtectedExeNeedsAbsoluteExistingRegularFile(t *testing.T) {
	if _, err := ProtectedExe("vpnsplit"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("relative: %v", err)
	}
	if _, err := ProtectedExe(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file must be refused")
	}
	if _, err := ProtectedExe(t.TempDir()); err == nil {
		t.Error("a directory must be refused")
	}
}

// A symbolic link is resolved, and what it leads to is judged: a link in a
// protected place to a file in a user's directory does not pass.
func TestProtectedExeJudgesTheTargetOfALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ProtectedExe(link); err == nil {
		t.Error("the target is in a user's directory")
	}
}

// What the system ships passes (Windows: cmd.exe).
func TestProtectedExeAcceptsSystemFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("see the Unix test below")
	}
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	got, err := ProtectedExe(exe)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !strings.EqualFold(got, exe) {
		t.Errorf("got %s", got)
	}
}

// As root: a directory made here with the usual rights passes, a group-writable
// file or directory does not.
func TestProtectedExeUnixModes(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root on Unix")
	}
	base, err := os.MkdirTemp("/opt", "vpnsplit-test-")
	if err != nil {
		t.Skip("cannot make a directory in /opt:", err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(base, "vpnsplit")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := ProtectedExe(exe); err != nil || got != exe {
		t.Fatalf("%q %v", got, err)
	}
	if err := os.Chmod(exe, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := ProtectedExe(exe); err == nil {
		t.Error("a group-writable file must not pass")
	}
	if err := os.Chmod(exe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := ProtectedExe(exe); err == nil {
		t.Error("a world-writable directory must not pass")
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	// a directory above that a user could replace
	sub := filepath.Join(base, "sub")
	if err := os.Mkdir(sub, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o777); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(sub, "bin")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(inner, "vpnsplit")
	if err := os.WriteFile(deep, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ProtectedExe(deep); err == nil {
		t.Error("a writable directory above the program must not pass")
	}
}
