//go:build windows

package sysexec

import (
	"path/filepath"
	"strings"
	"testing"
)

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[strings.ToUpper(k)] = v
	}
	return m
}

func TestCommandIsAbsoluteAndIgnoresPATH(t *testing.T) {
	evil := t.TempDir()
	t.Setenv("PATH", evil)
	t.Setenv("PATHEXT", ".EVIL")
	t.Setenv("PSModulePath", evil)
	for _, name := range []string{"route", "powershell"} {
		cmd := Command(name)
		if cmd.Err != nil {
			t.Fatalf("%s: %v", name, cmd.Err)
		}
		if !filepath.IsAbs(cmd.Path) {
			t.Errorf("%s: path %q is not absolute", name, cmd.Path)
		}
		sys, _, _ := systemDirs()
		if !strings.EqualFold(filepath.Dir(cmd.Path)[:len(sys)], sys) {
			t.Errorf("%s: %q is outside %s", name, cmd.Path, sys)
		}
		if cmd.Env == nil {
			t.Errorf("%s: environment is inherited", name)
		}
		for _, kv := range cmd.Env {
			if strings.Contains(strings.ToLower(kv), strings.ToLower(evil)) {
				t.Errorf("%s: user environment leaked: %s", name, kv)
			}
		}
	}
}

func TestUnknownToolRefused(t *testing.T) {
	for _, n := range []string{"cmd", "calc", `..\evil`, "ip"} {
		if cmd := Command(n); cmd.Err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestPowerShellEnvironment(t *testing.T) {
	t.Setenv("PSModulePath", `C:\evil`)
	cmd := PowerShell("1", map[string]string{"A": "x", "B": "y"})
	m := envMap(cmd.Env)
	sys, win, _ := systemDirs()
	if !strings.EqualFold(m["PSMODULEPATH"], filepath.Join(sys, `WindowsPowerShell\v1.0\Modules`)) {
		t.Errorf("PSModulePath = %q", m["PSMODULEPATH"])
	}
	if !strings.EqualFold(m["SYSTEMROOT"], win) || !strings.EqualFold(m["WINDIR"], win) {
		t.Errorf("SystemRoot/windir = %q %q", m["SYSTEMROOT"], m["WINDIR"])
	}
	if m["VS_A"] != "x" || m["VS_B"] != "y" {
		t.Errorf("data variables missing: %v", cmd.Env)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy Restricted", "-Command"} {
		if !strings.Contains(args, want) {
			t.Errorf("argument %s missing: %s", want, args)
		}
	}
}

// The real PowerShell sees only the system module path and a fixed PATH.
func TestPowerShellRealEnvironment(t *testing.T) {
	evil := t.TempDir()
	t.Setenv("PSModulePath", evil)
	t.Setenv("PATH", evil)
	out, err := PowerShell("[Console]::Out.Write($env:PSModulePath + '|' + $env:PATH)", nil).Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(out)), strings.ToLower(evil)) {
		t.Errorf("user path reached PowerShell: %s", out)
	}
	t.Logf("PSModulePath|PATH = %s", out)
}
