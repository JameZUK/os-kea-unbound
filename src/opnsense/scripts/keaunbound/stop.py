#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""Stop the kea-unbound DDNS listener (signals the daemon(8) supervisor)."""

import fcntl
import os
import signal
import subprocess
import sys
import time

RUN_DIR = "/var/run/keaunbound"
PIDFILE = os.path.join(RUN_DIR, "kea-unbound-ddns.pid")
SUPERVISOR_PID = os.path.join(RUN_DIR, "supervisor.pid")
START_LOCK = os.path.join(RUN_DIR, "start.lock")


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


def _cmdline(pid):
    """Full argv of pid. Prefer procstat(1): it reads the kernel's stored process
    args directly, so it still works when `kern.ps_arg_cache_limit` is small enough
    that ps(1)/pgrep -f report an EMPTY argv for a long command line. (Observed on a
    box with ps_arg_cache_limit=256: the listener's ~200-char argv exceeded the cache,
    ps showed nothing, and the ps-based identification below silently failed — so stop
    could neither find nor kill the listener.) Fall back to ps if procstat is absent."""
    try:
        out = subprocess.run(["procstat", "-c", str(pid)],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            tok = line.split(None, 2)
            if tok and tok[0].isdigit() and int(tok[0]) == pid:
                return tok[2] if len(tok) == 3 else ""
    except Exception:
        pass
    try:
        return subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


def _is_ours(pid):
    """True only if the live PID is actually our listener/supervisor — guards
    against a stale pidfile whose PID the OS has recycled for something else."""
    if not _alive(pid):
        return False
    out = _cmdline(pid)
    # Anchor to the actual interpreter+script invocation. A bare "kea-unbound-ddns"
    # substring would also match a "kea-unbound-ddns.log" tail, an editor on the .py,
    # or a grep — and _sweep_orphans would then SIGKILL a daemon(8) parenting any of
    # those. Require BOTH the python interpreter and the listener script.
    return "kea-unbound-ddns.py" in out and "python" in out


def _listener_pids():
    """Every live PID running the listener script, read via procstat -ac (the
    kernel's args, so it works under a small ps_arg_cache_limit), each re-confirmed
    with _is_ours() so a process that merely MENTIONS the path (a grep/awk/editor) is
    excluded. Falls back to pgrep -f."""
    pids = []
    try:
        out = subprocess.run(["procstat", "-ac"], capture_output=True,
                             text=True, timeout=10).stdout
        for line in out.splitlines():
            if "kea-unbound-ddns.py" not in line:
                continue
            tok = line.split(None, 1)
            if tok and tok[0].isdigit() and _is_ours(int(tok[0])):
                pids.append(int(tok[0]))
        return pids
    except Exception:
        return [p for p in _pgrep("-f", "kea-unbound-ddns.py") if _is_ours(p)]


def _pgrep(*args):
    """Return the PIDs matched by `pgrep <args>` (empty list on any failure)."""
    try:
        out = subprocess.run(["pgrep", *args], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        return []
    pids = []
    for tok in out.split():
        try:
            pids.append(int(tok))
        except ValueError:
            pass
    return pids


def _is_our_supervisor(pid):
    """True if `pid` is a daemon(8) supervisor of our listener. daemon(8) RETITLES
    itself to 'daemon: python3[child] (daemon)' after forking, so the script path is
    gone from its OWN command line and _is_ours() can't recognise it — we identify it
    by its child instead. Without this, _stop_impl() never signals the supervisor,
    `daemon -r` respawns the listener, and an orphan survives stop/teardown/uninstall."""
    if not _alive(pid):
        return False
    return any(_is_ours(kid) for kid in _pgrep("-P", str(pid)))


def _sweep_orphans():
    """Belt-and-suspenders cleanup for the case the pidfiles were lost (manual kill,
    empty pidfile, a pre-fix start.py): find any daemon(8) supervisor of our listener
    and kill it, then any lingering listener child. This is what makes stop truly
    idempotent and uninstall truly clean even when bookkeeping is out of sync."""
    for d in _pgrep("-x", "daemon"):
        # Re-check identity-and-liveness as close to the kill as possible: between
        # the pgrep snapshot and here a PID can die and be recycled, so confirm it's
        # still a daemon(8) supervising OUR listener right before signalling it.
        if _is_our_supervisor(d) and _alive(d):
            try:
                os.kill(d, signal.SIGKILL)
            except OSError:
                pass
    for k in _listener_pids():
        if _is_ours(k):
            try:
                os.kill(k, signal.SIGKILL)
            except OSError:
                pass


def stop(_locked=False):
    """Stop the listener. Takes the shared start.lock so a standalone stop (configd
    `keaunbound stop` / teardown) is mutually exclusive with a concurrent start/
    restart — otherwise the two race and can orphan a supervisor. start.py already
    holds the lock and calls stop(_locked=True) to avoid re-locking (self-deadlock)."""
    if _locked:
        return _stop_impl()
    os.makedirs(RUN_DIR, exist_ok=True)
    lk = open(START_LOCK, "w")
    try:
        fcntl.flock(lk, fcntl.LOCK_EX)
        return _stop_impl()
    finally:
        fcntl.flock(lk, fcntl.LOCK_UN)
        lk.close()


def _ours(pid):
    """The PID is ours whether it's the listener child or its (retitled) supervisor.

    Note: we identify the supervisor by its CHILD (_is_our_supervisor), never by bare
    provenance of the recorded supervisor.pid. Trusting "we wrote that pid" would, on
    PID reuse, let stop kill an unrelated daemon(8) (OPNsense runs many) — a far worse
    failure than the rare, self-healing orphan it would prevent. A supervisor caught
    in its short daemon(8) respawn gap (no child to match) is therefore left for the
    next start/stop to reap once it has respawned a child; the bind-retry in the
    listener removes the transient-bind-failure that used to create that gap."""
    return _is_ours(pid) or _is_our_supervisor(pid)


def _stop_impl():
    # Signal the supervisor first so it stops respawning the child. Only signal a
    # PID we've confirmed is ours (child OR the retitled daemon(8) supervisor).
    for path in (SUPERVISOR_PID, PIDFILE):
        pid = _read_pid(path)
        if _ours(pid):
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
        if _ours(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    # Catch supervisors/children the pidfiles no longer track (orphan case).
    _sweep_orphans()
    for path in (SUPERVISOR_PID, PIDFILE):
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == "__main__":
    stop()
    sys.exit(0)
