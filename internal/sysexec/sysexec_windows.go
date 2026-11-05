//go:build windows

package sysexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

// tools maps the names this program uses to their place under System32.
var tools = map[string]string{
	"powershell": `WindowsPowerShell\v1.0\powershell.exe`,
	"route":      `route.exe`,
}

func systemDirs() (sys, win string, err error) {
	if sys, err = windows.GetSystemDirectory(); err != nil {
		return "", "", err
	}
	if win, err = windows.GetWindowsDirectory(); err != nil {
		return "", "", err
	}
	return sys, win, nil
}

func lookPath(name string) (string, error) {
	rel, ok := tools[strings.ToLower(strings.TrimSuffix(name, ".exe"))]
	if !ok {
		return "", errors.New("not a known system tool")
	}
	sys, _, err := systemDirs()
	if err != nil {
		return "", err
	}
	path := filepath.Join(sys, rel)
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

func baseEnv() []string {
	sys, win, err := systemDirs()
	if err != nil {
		return []string{}
	}
	return envFor(sys, win)
}

// envFor is the whole environment of a child process: the system locations
// and nothing inherited. PSModulePath lists the system modules only, so no
// module from the user's Documents can shadow a cmdlet.
func envFor(sys, win string) []string {
	return []string{
		"SystemRoot=" + win,
		"windir=" + win,
		"SystemDrive=" + filepath.VolumeName(win),
		"ComSpec=" + filepath.Join(sys, "cmd.exe"),
		"PATH=" + sys + ";" + win + ";" + filepath.Join(sys, "Wbem"),
		"PATHEXT=.COM;.EXE;.BAT;.CMD",
		"PSModulePath=" + filepath.Join(sys, `WindowsPowerShell\v1.0\Modules`),
	}
}

// PowerShell returns a command that runs script in Windows PowerShell from
// System32 without profiles and with the execution policy Restricted. The
// script text must be a constant: every value reaches it through the
// environment as $env:VS_<key>, so data is never parsed as code.
func PowerShell(script string, env map[string]string) *exec.Cmd {
	cmd := Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Restricted", "-Command",
		"[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "+script)
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cmd.Env = append(cmd.Env, "VS_"+k+"="+env[k])
	}
	return cmd
}
