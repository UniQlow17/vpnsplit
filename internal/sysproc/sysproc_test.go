package sysproc

import (
	"os"
	"testing"
)

func TestSelfIsAlive(t *testing.T) {
	pid, start := Self()
	if pid != os.Getpid() {
		t.Fatalf("pid %d", pid)
	}
	if !Alive(pid, start) {
		t.Error("the current process must be alive")
	}
}

func TestReusedPidIsNotAlive(t *testing.T) {
	pid, start := Self()
	if start == 0 {
		t.Skip("start time is not available on this OS")
	}
	if Alive(pid, start+12345) {
		t.Error("same pid with another start time is a different process")
	}
}

func TestMissingPidIsNotAlive(t *testing.T) {
	if Alive(0, 0) || Alive(-5, 0) {
		t.Error("pid <= 0 is never alive")
	}
	if Alive(0x3ffffff0, 0) { // far above any real pid
		t.Error("a pid that does not exist must not be alive")
	}
}

func TestSameBootTime(t *testing.T) {
	if !sameBootTime("1000", "1300") || sameBootTime("1000", "5000") {
		t.Error("tolerance")
	}
	if !sameBootTime("", "5") || !sameBootTime("5", "") {
		t.Error("unknown boot id never proves a reboot")
	}
}

func TestBootIDStable(t *testing.T) {
	a, b := BootID(), BootID()
	if !SameBoot(a, b) {
		t.Errorf("%q vs %q", a, b)
	}
}

func TestAliveExact(t *testing.T) {
	pid, start := Self()
	if start == 0 {
		t.Skip("the start time of this process is not readable here")
	}
	if !AliveExact(pid, start) {
		t.Error("this very process")
	}
	if AliveExact(pid, start+1) {
		t.Error("another start time: a reused PID")
	}
	if AliveExact(pid, 0) {
		t.Error("an unrecorded start is no proof")
	}
	if AliveExact(0, start) || AliveExact(-1, start) {
		t.Error("no such PID")
	}
}
