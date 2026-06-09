#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Start (or restart) the kea-unbound DDNS listener under daemon(8) supervision.

Reads settings straight from /conf/config.xml (OPNsense/KeaUnbound/general),
resolves the qualifying suffix default from the firewall domain, then launches
the listener with daemon(8) -r (auto-respawn). Stops any existing instance first,
so `start` is idempotent and doubles as `restart`.
"""

import fcntl
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stop as stopper  # noqa: E402  (sibling script)

CONFIG = "/conf/config.xml"
DAEMON = "/usr/local/sbin/kea-unbound-ddns.py"
RUN_DIR = "/var/run/keaunbound"
PIDFILE = os.path.join(RUN_DIR, "kea-unbound-ddns.pid")
SUPERVISOR_PID = os.path.join(RUN_DIR, "supervisor.pid")
LOG_FILE = "/var/log/keaunbound/keaunbound.log"


def _text(node, path, default=""):
    if node is None:
        return default
    el = node.find(path)
    if el is not None and el.text:
        return el.text.strip()
    return default


def load_settings():
    try:
        root = ET.parse(CONFIG).getroot()
    except Exception:
        return None, ""
    gen = root.find("./OPNsense/KeaUnbound/general")
    domain = _text(root.find("./system"), "domain", "")
    return gen, domain


def build_args(gen, domain):
    port = _text(gen, "listener_port", "53535")
    args = [DAEMON, "--port", port,
            "--log-file", LOG_FILE,
            "--include-file", "/usr/local/etc/unbound.opnsense.d/keaunbound.conf",
            "--unbound-conf", "/var/unbound/unbound.conf",
            "--host-entries", "/var/unbound/host_entries.conf"]
    if _text(gen, "aggressive_cleanup", "1") == "1":
        args.append("--aggressive-cleanup")
    if _text(gen, "tsig_enabled", "1") == "1":
        # TSIG is REQUIRED whenever the user enabled it — independent of whether a
        # secret is present. The secret travels via the environment (tsig_secret_env),
        # NOT argv (argv is world-readable via ps(1) / /proc/<pid>/cmdline). If the
        # secret is somehow missing, the listener fails closed rather than silently
        # accepting unsigned updates — so we must NOT fall back to --no-tsig here.
        args += ["--tsig-name", _text(gen, "tsig_key_name", "keaunbound"),
                 "--tsig-algorithm", _text(gen, "tsig_algorithm", "hmac-sha256")]
    else:
        args.append("--no-tsig")
    # qualifying suffix isn't consumed by the listener (Kea/D2 forms FQDNs); it is
    # injected into Kea's config by the kea_sync hook in Phase 4. Resolved here so
    # the default (firewall domain) is visible in logs/diagnostics.
    _ = _text(gen, "qualifying_suffix") or domain
    return args


def tsig_secret_env(gen):
    """Build the subprocess environment carrying the TSIG secret out-of-band (not in
    argv). The daemon(8) wrapper inherits it and the listener reads it from the env."""
    env = dict(os.environ)
    if _text(gen, "tsig_enabled", "1") == "1" and _text(gen, "tsig_key_secret"):
        env["KEAUNBOUND_TSIG_SECRET"] = _text(gen, "tsig_key_secret")
    else:
        env.pop("KEAUNBOUND_TSIG_SECRET", None)
    return env


def _log(msg):
    line = "%s [INFO] start: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print("keaunbound: " + msg)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def _spawn(gen, domain):
    args = build_args(gen, domain)
    cmd = ["/usr/sbin/daemon", "-f", "-r", "-R", "5",
           "-p", PIDFILE, "-P", SUPERVISOR_PID,
           "/usr/local/bin/python3"] + args
    subprocess.run(cmd, env=tsig_secret_env(gen), check=False)


def _listener_up():
    """True iff the pidfile names a live process that is actually our listener."""
    try:
        with open(PIDFILE) as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return False
    return stopper._is_ours(pid)


def _spawn_and_verify(gen, domain, timeout=5.0):
    """Spawn the supervised listener and confirm it actually bound. daemon(8) -f
    forks and returns immediately, so a bad bind / fail-closed exit / configd race
    leaves nothing running with no error — poll for the pidfile to materialise and
    name a live listener of ours before declaring success."""
    _spawn(gen, domain)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _listener_up():
            return True
        time.sleep(0.25)
    return False


def main():
    os.makedirs(RUN_DIR, exist_ok=True)
    # Serialize start/restart against itself: two overlapping runs (e.g. a boot
    # configure racing a GUI apply) could each stop+spawn and orphan a supervisor
    # that then respawns a second listener on the same port. The lock makes the
    # stop+spawn atomic.
    lock = open(os.path.join(RUN_DIR, "start.lock"), "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        gen, domain = load_settings()
        if gen is None or _text(gen, "enabled") != "1":
            # Not enabled: make sure nothing is running and exit cleanly.
            stopper.stop(_locked=True)  # we already hold start.lock
            return 0
        # Idempotent: stop any existing instance before (re)starting.
        stopper.stop(_locked=True)  # we already hold start.lock
        started = _spawn_and_verify(gen, domain)
        if not started:
            # Observed configd-start flake: the spawn occasionally leaves no bound
            # listener. A clean respawn under the same lock reliably recovers it.
            # (A genuine fail-closed — TSIG required, no secret — will also land here
            # and stay down, which is the correct outcome; we surface it as non-zero.)
            _log("listener not up after spawn — retrying once")
            stopper.stop(_locked=True)
            started = _spawn_and_verify(gen, domain)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
    if not started:
        _log("ERROR: listener failed to start (no bound listener after retry)")
        return 1
    # Seed existing leases/reservations so DNS is populated immediately rather than
    # waiting for the next DDNS event. Best-effort; never blocks the listener start.
    sync = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lease-sync.py")
    if os.path.exists(sync):
        subprocess.run(["/usr/local/bin/python3", sync], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
