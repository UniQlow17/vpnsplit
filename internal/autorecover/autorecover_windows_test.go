//go:build windows

package autorecover

import (
	"strings"
	"testing"
)

// The scripts are constants: the path never reaches their text, only the environment.
func TestScriptsTakeDataFromTheEnvironment(t *testing.T) {
	for name, s := range map[string]string{"install": installScript, "remove": removeScript} {
		if !strings.Contains(s, "$env:VS_TASK") || !strings.Contains(s, "$env:VS_MARK") {
			t.Errorf("%s: the name and the mark must come from the environment", name)
		}
		if strings.Contains(s, TaskName) {
			t.Errorf("%s: the task name is in the text", name)
		}
	}
	if !strings.Contains(installScript, "-Execute $env:VS_EXE") || !strings.Contains(installScript, "'SYSTEM'") || !strings.Contains(installScript, "-AtStartup") {
		t.Error("the task must start the program from the environment at startup as SYSTEM")
	}
	if strings.Contains(installScript, `C:\`) {
		t.Error("a path in the script")
	}
	for name, s := range map[string]string{"install": installScript, "remove": removeScript} {
		if !strings.Contains(s, `-TaskPath '\'`) || !strings.Contains(s, "Count") || !strings.Contains(s, "S-1-5-18") || !strings.Contains(s, "Test-Ours") {
			t.Errorf("%s: the task must be looked up in the root folder, once, as SYSTEM, with the mark", name)
		}
	}
	if !strings.Contains(installScript, "Unregister-ScheduledTask") || strings.Contains(installScript, "-Force") {
		t.Error("our own task is deleted before it is registered anew; no -Force over somebody else's")
	}
	env := taskEnv(`C:\Program Files\vpnsplit\vpnsplit.exe`)
	if env["EXE"] != `C:\Program Files\vpnsplit\vpnsplit.exe` || env["TASK"] != TaskName || env["MARK"] != Mark {
		t.Errorf("%v", env)
	}
}
