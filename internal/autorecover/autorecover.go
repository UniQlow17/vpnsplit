// Package autorecover installs and removes the job that runs `vpnsplit recover`
// when the computer starts: a Task Scheduler task (Windows), a systemd unit
// (Linux) or a LaunchDaemon (macOS). It is installed only by the command
// `vpnsplit install-recover`, never on its own.
//
// The job runs the program with the rights of the system (SYSTEM, root), so
// whoever can replace the program or one of its directories gets those rights.
// Install therefore refuses a program that is not protected (see
// config.ProtectedExe). The path of the program is checked and reaches the job
// as a value: a PowerShell script gets it from the environment, a unit and a
// plist get it in a text built from a constant template, with a path that has
// passed ValidExePath (no character that means something to systemd, XML or the
// shell). The job is marked, and only a job with the mark is ever removed.
package autorecover

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Mark is what tells a job made here from anybody else's with the same name.
	Mark = "vpnsplit-managed"

	// TaskName is the name of the Task Scheduler task.
	TaskName = "vpnsplit-recover"
	// UnitName is the systemd unit.
	UnitName = "vpnsplit-recover.service"
	// Label is the LaunchDaemon label.
	Label = "com.vpnsplit.recover"

	unitDir  = "/etc/systemd/system"
	plistDir = "/Library/LaunchDaemons"

	maxPath = 1024
)

// ErrNotOurs is returned when a job with our name exists and does not carry our mark.
var ErrNotOurs = errors.New("exists and was not made by vpnsplit: left alone")

// ValidExePath checks the text of the path of the program for the system goos:
// an absolute, clean path (no "..", no empty parts) made of letters, digits,
// spaces and a few harmless signs. A character that systemd (quotes, backslash,
// %, $), XML, a shell or Task Scheduler (%) would read as something else is not
// allowed at all.
func ValidExePath(goos, p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case len(p) > maxPath:
		return errors.New("path too long")
	case !utf8.ValidString(p):
		return errors.New("path is not valid UTF-8")
	}
	var sep rune = '/'
	rest := p
	if goos == "windows" {
		sep = '\\'
		if len(p) < 3 || !isDriveLetter(rune(p[0])) || p[1] != ':' || p[2] != '\\' {
			return fmt.Errorf("%s: not a path of the form C:\\dir\\file (network and device paths are not accepted)", p)
		}
		rest = p[3:]
	} else {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("%s: not an absolute path", p)
		}
		rest = p[1:]
	}
	if rest == "" {
		return fmt.Errorf("%s: a directory, not a program", p)
	}
	for _, part := range strings.Split(rest, string(sep)) {
		switch {
		case part == "":
			return fmt.Errorf("%s: empty part in the path", p)
		case part == "." || part == "..":
			return fmt.Errorf("%s: not a clean path", p)
		case part != strings.TrimSpace(part) || strings.HasSuffix(part, "."):
			return fmt.Errorf("%s: a part of the path starts or ends with a space or a dot", p)
		}
		for _, r := range part {
			if !allowedRune(r) {
				return fmt.Errorf("%s: the character %q is not allowed in the path of the program", p, r)
			}
		}
	}
	return nil
}

func isDriveLetter(r rune) bool { return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' }

func allowedRune(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	return strings.ContainsRune(" _-.+,@=~()", r)
}

// unitMark is what tells a unit as ours; markLine is the first line of the unit.
const (
	unitMark = "# " + Mark + ": written by"
	markLine = unitMark + " `vpnsplit install-recover`, removed by `vpnsplit install-recover --remove`\n"
)

// UnitText is the systemd unit that runs `vpnsplit recover` once at boot.
func UnitText(exe string) (string, error) {
	if err := ValidExePath("linux", exe); err != nil {
		return "", err
	}
	return markLine + `[Unit]
Description=vpnsplit: finish the cleanup of an earlier run (routes, DNS entries)
After=local-fs.target

[Service]
Type=oneshot
ExecStart="` + exe + `" recover
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
`, nil
}

// plistMark is the comment that marks a plist as ours (it must not contain two hyphens in a row).
const (
	plistMarkStart = "<!-- " + Mark + ": written by"
	plistMark      = plistMarkStart + " `vpnsplit install-recover` -->"
)

// PlistText is the LaunchDaemon that runs `vpnsplit recover` once at boot.
func PlistText(exe string) (string, error) {
	if err := ValidExePath("darwin", exe); err != nil {
		return "", err
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
` + plistMark + `
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(exe) + `</string>
		<string>recover</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/var/log/vpnsplit-recover.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/vpnsplit-recover.log</string>
</dict>
</plist>
`, nil
}

// xmlEscape is for the text of an XML element. ValidExePath lets none of these
// through; this is the second line of defence.
func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// writeManaged writes content to path, which must not exist or must be a plain
// file that carries the mark. The file is written next to its place and moved
// there, so a reader never sees half of it.
func writeManaged(path string, content []byte, mark string, mode os.FileMode) error {
	if err := checkManaged(path, mark); err != nil {
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp) // a leftover of an earlier failed run (in a directory only root can write)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// checkManaged is nil if path does not exist or is a plain file with our mark.
func checkManaged(path, mark string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, ErrNotOurs)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte(mark)) {
		return fmt.Errorf("%s: %w", path, ErrNotOurs)
	}
	return nil
}

// removeManaged deletes path if it carries the mark; it reports whether the
// file was there. Somebody else's file is left alone (ErrNotOurs).
func removeManaged(path, mark string) (bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err := checkManaged(path, mark); err != nil {
		return true, err
	}
	if err := os.Remove(path); err != nil {
		return true, err
	}
	return true, nil
}

// Runner starts a system tool with arguments and returns what it printed.
type Runner func(tool string, args ...string) ([]byte, error)

func say(out io.Writer, format string, a ...any) { fmt.Fprintf(out, format+"\n", a...) }
