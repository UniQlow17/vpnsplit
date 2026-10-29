package autorecover

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

func writeSrc(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src-vpnsplit")
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCopyProgramAndRemove(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, programFileName())
	src := writeSrc(t, "one")
	if err := copyProgram(src, dir, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "one" {
		t.Fatalf("copy = %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, config.ProgramMarkName)); err != nil {
		t.Fatal("no marker")
	}
	// a second install replaces the copy
	if err := copyProgram(writeSrc(t, "two"), dir, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "two" {
		t.Fatalf("copy = %q", b)
	}
	// started from the copy itself: nothing to do
	if err := copyProgram(dest, dir, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest + ".tmp"); err == nil {
		t.Error("temporary file left")
	}
	if err := removeCopy(dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("the empty directory stays")
	}
}

func TestCopyProgramRefusesSomebodyElsesFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, programFileName())
	if err := os.WriteFile(dest, []byte("theirs"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := copyProgram(writeSrc(t, "x"), dir, dest)
	if !errors.Is(err, ErrNotOurs) {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "theirs" {
		t.Error("their file was changed")
	}
	// removal without the marker touches nothing
	if err := removeCopy(dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Error("their file was removed")
	}
}

func TestCopyProgramRefusesNotRegular(t *testing.T) {
	dir := t.TempDir()
	if err := copyProgram(dir, dir, filepath.Join(dir, "x")); err == nil {
		t.Error("a directory was copied")
	}
}

func TestRemoveKeepsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, programFileName())
	if err := copyProgram(writeSrc(t, "one"), dir, dest); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeCopy(dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("another file was removed")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("the copy stays")
	}
}
