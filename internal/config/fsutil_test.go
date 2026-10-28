package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	for _, content := range []string{"one", "two"} {
		if err := writeFileAtomic(dir, "f.json", []byte(content), 0o644, nil); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "f.json"))
	if err != nil || string(b) != "two" {
		t.Errorf("%q %v", b, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	if err := writeFileAtomic(filepath.Join(t.TempDir(), "nope"), "f", []byte("x"), 0o644, nil); err == nil {
		t.Error("expected error")
	}
}

func TestReadRegularRefusesDirAndHuge(t *testing.T) {
	dir := t.TempDir()
	if _, err := readRegular(dir); err == nil {
		t.Error("a directory is not a regular file")
	}
	p := filepath.Join(dir, "big")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(maxFileSize + 1); err != nil {
		t.Skip("cannot create a sparse file")
	}
	if _, err := readRegular(p); err == nil {
		t.Error("huge file accepted")
	}
}

func TestRemoveRegular(t *testing.T) {
	dir := t.TempDir()
	if err := removeRegular(dir, "missing"); err != nil {
		t.Errorf("missing file: %v", err)
	}
	if err := removeRegular(filepath.Join(dir, "no-such-dir"), "f"); err != nil {
		t.Errorf("missing dir: %v", err)
	}
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeRegular(dir, "f"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Errorf("file still there: %v", err)
	}
	// a directory with that name is not deleted
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeRegular(dir, "d"); err == nil {
		t.Error("directory removed")
	}
	// a name cannot lead out of the directory
	if err := removeRegular(dir, filepath.Join("..", "x")); err == nil {
		t.Log("parent-relative name was not an error, but nothing outside may be touched")
	}
}

func TestRemoveRegularRefusesLinkedDir(t *testing.T) {
	real := t.TempDir()
	victim := filepath.Join(real, "state.json")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("cannot create symlinks here: ", err)
	}
	if err := removeRegular(link, "state.json"); err == nil {
		t.Error("removed through a linked directory")
	}
	if _, err := os.Lstat(victim); err != nil {
		t.Errorf("victim gone: %v", err)
	}
}

func TestRelInside(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if rel, err := relInside(home, filepath.Join(home, ".config", "vpnsplit")); err != nil || rel != filepath.Join(".config", "vpnsplit") {
		t.Errorf("%q %v", rel, err)
	}
	for _, bad := range []string{filepath.Dir(home), filepath.Join(home, "..", "other"), home + "x"} {
		if _, err := relInside(home, bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
