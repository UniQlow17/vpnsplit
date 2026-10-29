package autorecover

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidExePath(t *testing.T) {
	good := map[string][]string{
		"linux":   {"/usr/local/bin/vpnsplit", "/opt/my tools/vpnsplit", "/usr/lib/vpn-split_1.2+b/vpnsplit", "/usr/local/bin/впн"},
		"darwin":  {"/usr/local/bin/vpnsplit", "/Library/Application Support/x/vpnsplit"},
		"windows": {`C:\Program Files\vpnsplit\vpnsplit.exe`, `D:\Tools (x86)\vpnsplit.exe`, `c:\a\b.exe`},
	}
	for goos, list := range good {
		for _, p := range list {
			if err := ValidExePath(goos, p); err != nil {
				t.Errorf("%s %q: %v", goos, p, err)
			}
		}
	}
	bad := map[string][]string{
		"linux": {"", "vpnsplit", "./vpnsplit", "/", "/usr/local/bin/", "/usr//bin/x", "/usr/../bin/x", "/usr/./bin/x",
			"/opt/a\"b/x", "/opt/a'b/x", "/opt/a\\b/x", "/opt/a%h/x", "/opt/$HOME/x", "/opt/a;b/x", "/opt/a\nb/x", "/opt/a\tb/x",
			"/opt/a`b/x", "/opt/a&b/x", "/opt/a<b/x", "/opt/a|b/x", "/opt/ x/x", "/opt/x /x", "/opt/x./x", "/opt/\xff/x", "/opt/a\x00b/x",
			"/" + strings.Repeat("a", 2000)},
		"darwin": {"/opt/a&amp;b/x", "/opt/a<b/x", "/opt/a\"b/x"},
		"windows": {`vpnsplit.exe`, `\\server\share\x.exe`, `\\?\C:\x.exe`, `C:vpnsplit.exe`, `C:\`, `C:\a\..\b.exe`, `C:\a\\b.exe`,
			`C:\a%PATH%\b.exe`, `C:\a&calc\b.exe`, `C:\a^b\b.exe`, `C:\a"b\b.exe`, `C:\a'b\b.exe`, `C:\a;b\b.exe`, `C:\a$b\b.exe`,
			`C:\a|b\b.exe`, `C:\a>b\b.exe`, `C:\a\b.exe `, `C:\a. \b.exe`, `C:\a:b\b.exe`, `C:/a/b.exe`, "C:\\a\nb\\b.exe"},
	}
	for goos, list := range bad {
		for _, p := range list {
			if err := ValidExePath(goos, p); err == nil {
				t.Errorf("%s %q must be refused", goos, p)
			}
		}
	}
}

func TestUnitText(t *testing.T) {
	text, err := UnitText("/usr/local/bin/vpnsplit")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# " + Mark + ": written by",
		"[Unit]", "[Service]", "[Install]",
		"Type=oneshot",
		`ExecStart="/usr/local/bin/vpnsplit" recover` + "\n",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	if !strings.HasPrefix(text, unitMark) {
		t.Error("the mark must be the first line")
	}
	for _, p := range []string{"/opt/a\"b/x", "/opt/a%hb/x", "relative/x", "/opt/a\nExecStart=/bin/sh/x"} {
		if _, err := UnitText(p); err == nil {
			t.Errorf("%q: the unit must not be built", p)
		}
	}
}

func TestPlistText(t *testing.T) {
	text, err := PlistText("/usr/local/bin/vpnsplit")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		plistMarkStart,
		"<key>Label</key>\n\t<string>com.vpnsplit.recover</string>",
		"<string>/usr/local/bin/vpnsplit</string>\n\t\t<string>recover</string>",
		"<key>RunAtLoad</key>\n\t<true/>",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	if inner := strings.TrimSuffix(strings.TrimPrefix(plistMark, "<!--"), "-->"); strings.Contains(inner, "--") {
		t.Error("an XML comment must not contain two hyphens")
	}
	for _, p := range []string{"/opt/a<b/x", "/opt/a&amp;b/x", "/opt/a</string><string>x/x"} {
		if _, err := PlistText(p); err == nil {
			t.Errorf("%q: the plist must not be built", p)
		}
	}
	if got := xmlEscape(`a&b<c>"d'`); got != "a&amp;b&lt;c&gt;&quot;d&apos;" {
		t.Error(got)
	}
}

type calls struct {
	list []string
	fail map[string]error
}

func (c *calls) run(tool string, args ...string) ([]byte, error) {
	line := tool + " " + strings.Join(args, " ")
	c.list = append(c.list, line)
	return []byte("out"), c.fail[line]
}

func TestInstallAndRemoveUnit(t *testing.T) {
	dir := t.TempDir()
	c := &calls{}
	var out bytes.Buffer
	if err := installUnit(dir, "/usr/local/bin/vpnsplit", c.run, &out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, UnitName)
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), `ExecStart="/usr/local/bin/vpnsplit" recover`) {
		t.Fatalf("%v\n%s", err, b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
			t.Errorf("mode %v", fi.Mode())
		}
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("the temporary file is left")
	}
	if got := strings.Join(c.list, "|"); got != "systemctl daemon-reload|systemctl enable "+UnitName {
		t.Errorf("calls: %s", got)
	}
	// installing again replaces our own file
	if err := installUnit(dir, "/opt/vpnsplit", c.run, &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), `"/opt/vpnsplit"`) {
		t.Errorf("not replaced:\n%s", b)
	}
	c.list = nil
	if err := removeUnit(dir, c.run, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("the unit is not removed")
	}
	if got := strings.Join(c.list, "|"); got != "systemctl disable "+UnitName+"|systemctl daemon-reload" {
		t.Errorf("calls: %s", got)
	}
	// removing what is not there is not an error
	c.list = nil
	if err := removeUnit(dir, c.run, &out); err != nil || len(c.list) != 0 || !strings.Contains(out.String(), "not installed") {
		t.Errorf("%v %v %s", err, c.list, out.String())
	}
}

// A file of the same name that is not ours is neither replaced nor removed.
func TestUnitOfSomebodyElseIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, UnitName)
	const theirs = "[Service]\nExecStart=/bin/true\n"
	if err := os.WriteFile(path, []byte(theirs), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &calls{}
	if err := installUnit(dir, "/usr/local/bin/vpnsplit", c.run, &bytes.Buffer{}); !errors.Is(err, ErrNotOurs) {
		t.Errorf("install over somebody else's: %v", err)
	}
	if err := removeUnit(dir, c.run, &bytes.Buffer{}); !errors.Is(err, ErrNotOurs) {
		t.Errorf("remove somebody else's: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != theirs {
		t.Errorf("changed:\n%s", b)
	}
	if len(c.list) != 0 {
		t.Errorf("systemctl was called: %v", c.list)
	}
}

// The unit is not written through a link or over a directory.
func TestUnitPathThatIsNotAPlainFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, UnitName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := installUnit(dir, "/usr/local/bin/vpnsplit", (&calls{}).run, &bytes.Buffer{}); !errors.Is(err, ErrNotOurs) {
		t.Errorf("a directory: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	d2 := t.TempDir()
	target := filepath.Join(d2, "target")
	if err := os.WriteFile(target, []byte("# "+Mark+": x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(d2, UnitName)); err != nil {
		t.Fatal(err)
	}
	if err := installUnit(d2, "/usr/local/bin/vpnsplit", (&calls{}).run, &bytes.Buffer{}); !errors.Is(err, ErrNotOurs) {
		t.Errorf("a link: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "# "+Mark+": x\n" {
		t.Error("written through the link")
	}
}

// Without a running systemd the file is still removed, with a warning.
func TestRemoveUnitWithoutSystemd(t *testing.T) {
	dir := t.TempDir()
	if err := installUnit(dir, "/usr/local/bin/vpnsplit", (&calls{}).run, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	c := &calls{fail: map[string]error{"systemctl disable " + UnitName: errors.New("no systemd"), "systemctl daemon-reload": errors.New("no systemd")}}
	var out bytes.Buffer
	if err := removeUnit(dir, c.run, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, UnitName)); err == nil {
		t.Error("not removed")
	}
	if !strings.Contains(out.String(), "warning") {
		t.Errorf("no warning: %s", out.String())
	}
}

func TestInstallUnitReportsSystemctlFailure(t *testing.T) {
	c := &calls{fail: map[string]error{"systemctl enable " + UnitName: errors.New("boom")}}
	err := installUnit(t.TempDir(), "/usr/local/bin/vpnsplit", c.run, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("%v", err)
	}
}

func TestInstallAndRemovePlist(t *testing.T) {
	dir := t.TempDir()
	c := &calls{}
	var out bytes.Buffer
	if err := installPlist(dir, "/usr/local/bin/vpnsplit", c.run, &out, false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, Label+".plist")
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), "<string>recover</string>") {
		t.Fatalf("%v\n%s", err, b)
	}
	want := "launchctl bootout system/" + Label + "|launchctl bootstrap system " + path
	if got := strings.Join(c.list, "|"); got != want {
		t.Errorf("calls: %s", got)
	}
	c.list = nil
	if err := removePlist(dir, c.run, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("not removed")
	}
	if got := strings.Join(c.list, "|"); got != "launchctl bootout system/"+Label {
		t.Errorf("calls: %s", got)
	}
	// somebody else's plist
	if err := os.WriteFile(path, []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removePlist(dir, c.run, &out); !errors.Is(err, ErrNotOurs) {
		t.Errorf("%v", err)
	}
	if err := installPlist(dir, "/usr/local/bin/vpnsplit", c.run, &out, false); !errors.Is(err, ErrNotOurs) {
		t.Errorf("%v", err)
	}
}
