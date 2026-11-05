package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMachineFileRefuses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	// a file in a temporary directory is never the system's: the owner is the
	// user, or (as root) the directory above is writable by others
	if _, err := ReadMachineFile(p, 10); err == nil {
		t.Error("a file of a temporary folder was read")
	}
	if _, err := ReadMachineFile("relative", 10); err == nil {
		t.Error("a relative path read")
	}
	if _, err := ReadMachineFile(p, 0); err == nil {
		t.Error("bad limit accepted")
	}
	if _, err := ReadMachineFile(filepath.Join(dir, "missing"), 10); err == nil {
		t.Error("a missing file read")
	}
}
