#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""Stop the kea-unbound DDNS listener (signals the daemon(8) supervisor)."""

import os
import signal
import subprocess
import sys
import time

RUN_DIR = "/var/run/keaunbound"
PIDFILE = os.path.join(RUN_DIR, "kea-unbound-ddns.pid")
SUPERVISOR_PID = os.path.join(RUN_DIR, "supervisor.pid")


def _read_pid(path):
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _is_ours(pid):
    """True only if the live PID is actually our listener/supervisor — guards
    against a stale pidfile whose PID the OS has recycled for something else."""
    if not _alive(pid):
        return False
    try:
        out = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return False
    return "kea-unbound-ddns" in out


def stop():
    # Signal the supervisor first so it stops respawning the child. Only signal a
    # PID we've confirmed is ours.
    for path in (SUPERVISOR_PID, PIDFILE):
        pid = _read_pid(path)
        if _is_ours(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    # Wait for the child to exit.
    deadline = time.time() + 10
    while time.time() < deadline:
        if not _is_ours(_read_pid(PIDFILE)):
            break
        time.sleep(0.25)
    # Force-kill anything of ours that lingers.
    for path in (SUPERVISOR_PID, PIDFILE):
        pid = _read_pid(path)
        if _is_ours(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    for path in (SUPERVISOR_PID, PIDFILE):
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == "__main__":
    stop()
    sys.exit(0)
