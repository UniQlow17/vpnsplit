//go:build unix

package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWriteFileAtomicDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	// planted links: the final name and the old fixed temporary name
	for _, n := range []string{"state.json", "state.json.tmp"} {
		if err := os.Symlink(victim, filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeFileAtomic(dir, "state.json", []byte("new"), 0o600, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Errorf("symlink target was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "state.json")); string(b) != "new" {
		t.Errorf("state.json = %q", b)
	}
	if fi, _ := os.Lstat(filepath.Join(dir, "state.json")); fi.Mode()&os.ModeSymlink != 0 {
		t.Error("state.json is still a symlink")
	}
}

func TestWriteFileAtomicRefusesSymlinkedDir(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(link, "f", []byte("x"), 0o644, nil); err == nil {
		t.Error("wrote through a symlinked directory")
	}
	if entries, _ := os.ReadDir(real); len(entries) != 0 {
		t.Errorf("files appeared in the target: %v", entries)
	}
}

func TestWriteUserFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(victim, []byte("precious"), 0o600)
	link := filepath.Join(dir, "export.txt")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteUserFile(link, []byte("rules")); err == nil {
		t.Error("expected error")
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Errorf("victim changed: %q", b)
	}
	if err := WriteUserFile(filepath.Join(dir, "ok.txt"), []byte("rules")); err != nil {
		t.Error(err)
	}
}

func TestReadRegularRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t")
	_ = os.WriteFile(target, []byte("{}"), 0o600)
	link := filepath.Join(dir, "l")
	_ = os.Symlink(target, link)
	if _, err := readRegular(link); err == nil {
		t.Error("symlink accepted")
	}
}

func TestSecureDirUnix(t *testing.T) {
	uid := os.Getuid()
	base := t.TempDir()

	// created with 0700
	p := filepath.Join(base, "state")
	if _, err := secureDirUnix(p, false, uid); !os.IsNotExist(err) {
		t.Errorf("missing dir without create: %v", err)
	}
	if _, err := secureDirUnix(p, true, uid); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}

	// too open but ours: tightened
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := secureDirUnix(p, false, uid); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o700 {
		t.Errorf("mode not tightened: %v", fi.Mode().Perm())
	}

	// somebody else's
	if _, err := secureDirUnix(p, false, uid+1); err == nil {
		t.Error("foreign owner accepted")
	}

	// symlink, even to a good directory
	link := filepath.Join(base, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := secureDirUnix(link, true, uid); err == nil {
		t.Error("symlink accepted")
	}

	// a file
	f := filepath.Join(base, "file")
	_ = os.WriteFile(f, nil, 0o600)
	if _, err := secureDirUnix(f, true, uid); err == nil {
		t.Error("file accepted")
	}
}

func TestEnsureUserDirStaysInHome(t *testing.T) {
	home := t.TempDir()
	o := &owner{uid: os.Getuid(), gid: os.Getgid(), home: home}
	if err := ensureUserDir(filepath.Join(home, ".config", "vpnsplit"), o); err != nil {
		t.Fatal(err)
	}
	// .config replaced by a link out of home
	home2 := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(home2, ".config")); err != nil {
		t.Fatal(err)
	}
	o2 := &owner{uid: os.Getuid(), gid: os.Getgid(), home: home2}
	if err := ensureUserDir(filepath.Join(home2, ".config", "vpnsplit"), o2); err == nil {
		t.Error("directory outside home accepted")
	}
}

func TestWriteFileAtomicForOwnerStaysInHome(t *testing.T) {
	home := t.TempDir()
	o := &owner{uid: os.Getuid(), gid: os.Getgid(), home: home}
	dir := filepath.Join(home, ".config", "vpnsplit")
	if err := ensureUserDir(dir, o); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(dir, "config.json", []byte("{}"), 0o644, o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config.json")); string(b) != "{}" {
		t.Errorf("%q", b)
	}
	outside := t.TempDir()
	if err := writeFileAtomic(outside, "x", []byte("x"), 0o644, o); err == nil {
		t.Error("wrote outside the home directory as root")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("files outside: %v", entries)
	}
}

func TestEnsureUserDirAllowsInnerLinkInsideHome(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "dotfiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dotfiles", filepath.Join(home, ".config")); err != nil { // relative: os.Root refuses absolute targets
		t.Fatal(err)
	}
	o := &owner{uid: os.Getuid(), gid: os.Getgid(), home: home}
	if err := ensureUserDir(filepath.Join(home, ".config", "vpnsplit"), o); err != nil {
		t.Fatalf("link inside home refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "dotfiles", "vpnsplit")); err != nil {
		t.Error(err)
	}
}

func TestEnsureUserDirRefusesLinkedLastComponent(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(home, ".config", "vpnsplit")); err != nil {
		t.Fatal(err)
	}
	o := &owner{uid: os.Getuid(), gid: os.Getgid(), home: home}
	if err := ensureUserDir(filepath.Join(home, ".config", "vpnsplit"), o); err == nil {
		t.Error("linked directory accepted")
	}
	if err := ensureUserDir(filepath.Join(t.TempDir(), "x"), o); err == nil {
		t.Error("directory outside home accepted")
	}
}

func TestReadRegularRefusesFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	if _, err := readRegular(p); err == nil {
		t.Error("fifo accepted")
	}
}

// os.Root treats an absolute link target as leaving the root, even if it
// points back into the home: that is stricter than needed, and safe.
func TestEnsureUserDirRefusesAbsoluteInnerLink(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "dotfiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "dotfiles"), filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
	o := &owner{uid: os.Getuid(), gid: os.Getgid(), home: home}
	if err := ensureUserDir(filepath.Join(home, ".config", "vpnsplit"), o); err == nil {
		t.Error("absolute link accepted")
	}
}
