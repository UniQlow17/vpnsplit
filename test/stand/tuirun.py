#!/usr/bin/env python3
"""Runs the vpnsplit menu (TUI) in the client namespace on a pseudo-terminal,
waits until it is ready, ends it one way and prints the exit status.
Usage: tuirun.py <q|tq|ctrlc|sigterm|sighup|hangup|offon|key1q> <ready> <binary>

  ready    a shell command that succeeds when the menu has done its start, or
           "screen:<word>" to wait until the word is on the screen

  q        presses q
  tq       presses t (take over the routes of apply/watch), waits for the
           confirmation on the screen, then presses q
  ctrlc    sends the Ctrl+C key (raw mode: arrives as a key)
  sigterm  SIGTERM to the process (what a closed Windows console becomes)
  sighup   SIGHUP to the process
  hangup   closes the terminal (the kernel sends SIGHUP: a closed terminal window)
  offon    the switch "Разделение": presses 1 (OFF), waits for the result, runs the
           shell command $TUI_CHECK_OFF (prints OFF_CHECK=<rc>), presses a key, presses 1
           again (ON), waits for the result, runs $TUI_CHECK_ON (prints ON_CHECK=<rc>),
           then presses q
  key1q    presses 1 and checks that the menu refuses (it tells about [t]), then q

Environment (optional):
  TUI_ROWS, TUI_COLS   the size of the terminal (default 40x120)
  TUI_ENV              extra "K=V" variables for the program, separated by spaces
  TUI_ARGS             extra arguments of the program, separated by spaces
  TUI_EMULATE_CSI=1    act as the terminal emulator for the sequence CSI 8;rows;cols t
                       (xterm): the size of the pty is set as asked; prints
                       RESIZE=<rows>x<cols> for each request

Prints: EXIT=<code> and the tail of the screen output.
"""
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time

mode, ready, binary = sys.argv[1], sys.argv[2], sys.argv[3]
rows = int(os.environ.get("TUI_ROWS", "40"))
cols = int(os.environ.get("TUI_COLS", "120"))
extra_env = os.environ.get("TUI_ENV", "").split()
extra_args = os.environ.get("TUI_ARGS", "").split()
emulate_csi = os.environ.get("TUI_EMULATE_CSI") == "1"

pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execvp("ip", ["ip", "netns", "exec", "client", "env", "HOME=/root"] + extra_env + [binary] + extra_args)

fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
buf = bytearray()
closed = threading.Event()
resizes = []
csi = re.compile(rb"\x1b\[8;(\d+);(\d+)t")


def reader():
    while not closed.is_set():
        try:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                data = os.read(fd, 65536)
                if not data:
                    return
                buf.extend(data)
                if emulate_csi:
                    # what an xterm does with the request: the window (the pty) gets the size
                    for m in list(csi.finditer(bytes(buf)))[len(resizes):]:
                        want = (int(m.group(1)), int(m.group(2)))
                        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", want[0], want[1], 0, 0))
                        resizes.append(want)
        except OSError:
            return


t = threading.Thread(target=reader, daemon=True)
t.start()


def screen_has(word, since=0):
    return word in bytes(buf[since:]).decode(errors="replace")


def wait_screen(word, since=0, secs=15):
    end_wait = time.time() + secs
    while not screen_has(word, since) and time.time() < end_wait:
        time.sleep(0.2)
    return screen_has(word, since)


def is_ready():
    if ready.startswith("screen:"):
        return screen_has(ready[len("screen:"):])
    return subprocess.run(ready, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def fail(code):
    os.kill(pid, signal.SIGKILL)
    print("EXIT=" + code)
    print(buf.decode(errors="replace")[-1500:])
    sys.exit(0)


def check(name):
    cmd = os.environ.get(name, "true")
    return subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


deadline = time.time() + 40
while time.time() < deadline:
    if is_ready():
        break
    time.sleep(0.3)
else:
    fail("not-ready")

time.sleep(0.5)
if mode == "q":
    os.write(fd, b"q")
elif mode == "tq":
    os.write(fd, b"t")
    if not wait_screen("забраны", 0, 10):
        fail("no-takeover")
    time.sleep(0.3)
    os.write(fd, b"q")
elif mode == "offon":
    mark = len(buf)
    os.write(fd, b"1")
    if not wait_screen("Снято записей", mark):
        fail("no-off-result")
    time.sleep(0.5)
    print("OFF_CHECK=%d" % check("TUI_CHECK_OFF"))
    print("OFF_CHECK2=%d" % check("TUI_CHECK_OFF2"))
    off_screen = bytes(buf[mark:]).decode(errors="replace")
    mark = len(buf)
    os.write(fd, b" ")  # leave the result screen
    time.sleep(0.8)
    print("OFF_STATUS=%d" % (1 if "Разделение ВЫКЛ" in off_screen else 0))
    mark = len(buf)
    os.write(fd, b"1")
    if not wait_screen("Применение маршрутов", mark):
        fail("no-on-result")
    time.sleep(0.5)
    print("ON_CHECK=%d" % check("TUI_CHECK_ON"))
    os.write(fd, b" ")
    time.sleep(0.5)
    os.write(fd, b"q")
elif mode == "key1q":
    mark = len(buf)
    os.write(fd, b"1")
    print("REFUSED=%d" % (1 if wait_screen("[t]", mark, 5) else 0))
    time.sleep(0.3)
    os.write(fd, b"q")
elif mode == "ctrlc":
    os.write(fd, b"\x03")
elif mode == "sigterm":
    os.kill(pid, signal.SIGTERM)
elif mode == "sighup":
    os.kill(pid, signal.SIGHUP)
elif mode == "hangup":
    closed.set()
    t.join()
    os.close(fd)
else:
    raise SystemExit("unknown mode " + mode)

code = None
end = time.time() + 15
while time.time() < end:
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        code = os.waitstatus_to_exitcode(status)
        break
    time.sleep(0.1)
if code is None:
    os.kill(pid, signal.SIGKILL)
    code = "timeout"
time.sleep(0.2)
closed.set()
for r in resizes:
    print("RESIZE=%dx%d" % r)
print("HINT=%d" % (1 if "увеличьте" in bytes(buf).decode(errors="replace") else 0))
print("EXIT=%s" % code)
if mode != "hangup":
    time.sleep(0.2)
    print(buf.decode(errors="replace")[-700:])
