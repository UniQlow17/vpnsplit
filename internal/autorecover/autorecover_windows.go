//go:build windows

package autorecover

import (
	"fmt"
	"io"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// The scripts are constants: the path, the name of the task and the mark reach
// them as $env:VS_EXE, $env:VS_TASK and $env:VS_MARK, never as text of the script.

// ourTask says whether a task is ours: in the root folder of the scheduler,
// run as SYSTEM (S-1-5-18) and carrying the mark in its description. All three
// must hold; a task of somebody else with the same name is never touched.
const ourTask = `function Test-Ours($t) {
  if ($t.TaskPath -ne '\') { return $false }
  if (([string]$t.Description).IndexOf($env:VS_MARK) -lt 0) { return $false }
  try { $sid = (New-Object System.Security.Principal.NTAccount([string]$t.Principal.UserId)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { return $false }
  return ($sid -eq 'S-1-5-18')
}
`

// installScript registers the task (at the start of the computer, as SYSTEM, the
// highest rights). A task of ours is deleted first, so the new one gets a fresh
// security descriptor; a task of that name that is not ours stops the install.
const installScript = `$ErrorActionPreference = 'Stop'
` + ourTask + `$old = @(Get-ScheduledTask -TaskPath '\' -TaskName $env:VS_TASK -ErrorAction SilentlyContinue)
if ($old.Count -gt 1) { throw 'more than one task with this name: left alone' }
if ($old.Count -eq 1) {
  if (-not (Test-Ours $old[0])) { throw 'a task with this name exists and was not made by vpnsplit' }
  Unregister-ScheduledTask -TaskPath '\' -TaskName $env:VS_TASK -Confirm:$false
}
$action = New-ScheduledTaskAction -Execute $env:VS_EXE -Argument 'recover'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$desc = $env:VS_MARK + ': runs "vpnsplit recover" at start to finish the cleanup of an earlier run'
Register-ScheduledTask -TaskPath '\' -TaskName $env:VS_TASK -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $desc | Out-Null
'installed'
`

// removeScript deletes the task if it is ours.
const removeScript = `$ErrorActionPreference = 'Stop'
` + ourTask + `$t = @(Get-ScheduledTask -TaskPath '\' -TaskName $env:VS_TASK -ErrorAction SilentlyContinue)
if ($t.Count -eq 0) { 'absent'; exit 0 }
if ($t.Count -gt 1 -or -not (Test-Ours $t[0])) { throw 'a task with this name exists and was not made by vpnsplit: left alone' }
Unregister-ScheduledTask -TaskPath '\' -TaskName $env:VS_TASK -Confirm:$false
'removed'
`

// taskEnv is what the scripts get.
func taskEnv(exe string) map[string]string {
	return map[string]string{"EXE": exe, "TASK": TaskName, "MARK": Mark}
}

// Install registers the task of Task Scheduler that runs `vpnsplit recover` at
// the start of the computer as SYSTEM. The task starts a copy of exe made in
// %ProgramFiles%\vpnsplit (see program.go). The caller must be an administrator.
func Install(exe string, out io.Writer) error {
	full, err := installProgram(exe, out)
	if err != nil {
		return err
	}
	o, err := sysexec.PowerShell(installScript, taskEnv(full)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("register the task %s: %w: %s", TaskName, err, trim(o))
	}
	say(out, "task %s installed: `%s recover` runs as SYSTEM at every start of the computer (not started now)", TaskName, full)
	return nil
}

// Remove deletes the task made by Install, if it is ours.
func Remove(out io.Writer) error {
	o, err := sysexec.PowerShell(removeScript, taskEnv("")).CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove the task %s: %w: %s", TaskName, err, trim(o))
	}
	if strings.Contains(string(o), "absent") {
		say(out, "not installed: there is no task %s", TaskName)
		return removeProgram(out)
	}
	say(out, "task %s removed", TaskName)
	return removeProgram(out)
}
