#!/usr/bin/env python3
"""Runs the vpnsplit menu (TUI) in the client namespace on a pseudo-terminal,
waits until it is ready, ends it one way and prints the exit status.
Usage: tuirun.py <q|tq|ctrlc|sigterm|sighup|hangup> <ready> <binary>

  ready    a shell command that succeeds when the menu has done its start, or
           "screen:<word>" to wait until the word is on the screen

  q        presses q
  tq       presses t (take over the routes of apply/watch), waits for the
           confirmation on the screen, then presses q
  ctrlc    sends the Ctrl+C key (raw mode: arrives as a key)
  sigterm  SIGTERM to the process (what a closed Windows console becomes)
  sighup   SIGHUP to the process
  hangup   closes the terminal (the kernel sends SIGHUP: a closed terminal window)
Prints: EXIT=<code> and the tail of the screen output.
"""
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time

mode, ready, binary = sys.argv[1], sys.argv[2], sys.argv[3]

pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execvp("ip", ["ip", "netns", "exec", "client", "env", "HOME=/root", binary])

fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
buf = bytearray()
closed = threading.Event()


def reader():
    while not closed.is_set():
        try:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                data = os.read(fd, 65536)
                if not data:
                    return
                buf.extend(data)
        except OSError:
            return


t = threading.Thread(target=reader, daemon=True)
t.start()


def screen_has(word):
    return word in buf.decode(errors="replace")


def is_ready():
    if ready.startswith("screen:"):
        return screen_has(ready[len("screen:"):])
    return subprocess.run(ready, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def fail(code):
    os.kill(pid, signal.SIGKILL)
    print("EXIT=" + code)
    print(buf.decode(errors="replace")[-1500:])
    sys.exit(0)


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
    end_wait = time.time() + 10
    while not screen_has("забраны") and time.time() < end_wait:
        time.sleep(0.2)
    if not screen_has("забраны"):
        fail("no-takeover")
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
closed.set()
print("EXIT=%s" % code)
if mode != "hangup":
    time.sleep(0.2)
    print(buf.decode(errors="replace")[-700:])
