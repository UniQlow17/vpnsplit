package clientcfg

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeProfile points the profile of the user (and so the config directory) at a
// temporary directory and returns the config directory.
func fakeProfile(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SUDO_USER", "")
	t.Setenv("PKEXEC_UID", "")
	cfg := filepath.Join(home, ".config")
	switch runtime.GOOS {
	case "windows":
		cfg = filepath.Join(home, "AppData", "Roaming")
		t.Setenv("APPDATA", cfg)
	case "darwin":
		cfg = filepath.Join(home, "Library", "Application Support")
	default:
		t.Setenv("XDG_CONFIG_HOME", cfg)
	}
	return cfg
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanTunReadsConfigs(t *testing.T) {
	cfg := fakeProfile(t)
	write(t, filepath.Join(cfg, "mihomo", "config.yaml"), "tun:\n  enable: true\n  strict-route: true\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 28.0.0.1/8\n")
	write(t, filepath.Join(cfg, "sing-box", "config.json"), `{"dns":{"fakeip":{"enabled":true,"inet4_range":"198.19.0.0/16"}}}`)
	var r Result
	r.scanTun()
	if len(r.Tun) < 2 {
		t.Fatalf("read %d configs: %+v", len(r.Tun), r.Tun)
	}
	got := map[string]bool{}
	for _, p := range r.FakeRanges {
		got[p.String()] = true
	}
	if !got["28.0.0.0/8"] || !got["198.19.0.0/16"] {
		t.Errorf("ranges %v", r.FakeRanges)
	}
	var mihomo TunCfg
	for _, c := range r.Tun {
		if c.Client == "Mihomo" {
			mihomo = c
		}
	}
	if !mihomo.StrictRoute || mihomo.Path == "" {
		t.Errorf("mihomo: %+v", mihomo)
	}
}

func TestScanTunRefusesLinksAndBigFiles(t *testing.T) {
	cfg := fakeProfile(t)
	target := filepath.Join(t.TempDir(), "real.yaml")
	write(t, target, "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 28.0.0.0/8\n")
	link := filepath.Join(cfg, "mihomo", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	var r Result
	r.scanTun()
	if len(r.Tun) != 0 || len(r.FakeRanges) != 0 {
		t.Errorf("a symlink was followed: %+v", r)
	}
	// a file over the limit
	os.Remove(link)
	write(t, link, "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 28.0.0.0/8\n#"+strings.Repeat("x", MaxConfigSize))
	r = Result{}
	r.scanTun()
	if len(r.Tun) != 0 {
		t.Errorf("a big file was read: %+v", r)
	}
	// a directory in place of the file
	os.Remove(link)
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	r = Result{}
	r.scanTun()
	if len(r.Tun) != 0 {
		t.Errorf("a directory was read: %+v", r)
	}
}

func TestCachedReusesResult(t *testing.T) {
	cfg := fakeProfile(t)
	fullCache.mu.Lock()
	fullCache.at = fullCache.at.Add(-1 << 40)
	fullCache.mu.Unlock()
	write(t, filepath.Join(cfg, "mihomo", "config.yaml"), "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 28.0.0.0/8\n")
	a := Cached(time.Hour)
	write(t, filepath.Join(cfg, "mihomo", "config.yaml"), "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 29.0.0.0/8\n")
	b := Cached(time.Hour)
	if len(a.FakeRanges) != 1 || len(b.FakeRanges) != 1 || a.FakeRanges[0] != b.FakeRanges[0] {
		t.Errorf("not reused: %v %v", a.FakeRanges, b.FakeRanges)
	}
	fullCache.mu.Lock()
	fullCache.at = fullCache.at.Add(-1 << 40)
	fullCache.mu.Unlock()
	c := Cached(0)
	if len(c.FakeRanges) != 1 || c.FakeRanges[0].String() != "29.0.0.0/8" {
		t.Errorf("not refreshed: %v", c.FakeRanges)
	}
}
