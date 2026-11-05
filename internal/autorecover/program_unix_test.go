//go:build unix

package autorecover

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// With root rights (the container of the stand): the real fixed directory.
func TestInstallProgramAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: it writes into the fixed directory of the system")
	}
	dir, err := config.MachineProgramDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); err == nil {
		t.Skipf("%s exists already", dir)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	var out bytes.Buffer
	full, err := installProgram(writeSrc(t, "binary"), &out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if full != filepath.Join(dir, "vpnsplit") {
		t.Errorf("path = %s", full)
	}
	fi, err := os.Stat(full)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("%v %v", fi, err)
	}
	// again: the copy is replaced
	if _, err := installProgram(writeSrc(t, "binary2"), &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(full); string(b) != "binary2" {
		t.Errorf("copy = %q", b)
	}
	if err := removeProgram(&out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); err == nil {
		t.Error("the directory stays")
	}
}
