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

import os
import subprocess
import sys
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
            "--include-file", "/var/unbound/etc/keaunbound.conf",
            "--unbound-conf", "/var/unbound/unbound.conf",
            "--host-entries", "/var/unbound/host_entries.conf"]
    if _text(gen, "aggressive_cleanup", "1") == "1":
        args.append("--aggressive-cleanup")
    if _text(gen, "tsig_enabled", "1") == "1" and _text(gen, "tsig_key_secret"):
        args += ["--tsig-name", _text(gen, "tsig_key_name", "keaunbound"),
                 "--tsig-secret", _text(gen, "tsig_key_secret"),
                 "--tsig-algorithm", _text(gen, "tsig_algorithm", "hmac-sha256")]
    else:
        args.append("--no-tsig")
    # qualifying suffix isn't consumed by the listener (Kea/D2 forms FQDNs); it is
    # injected into Kea's config by the kea_sync hook in Phase 4. Resolved here so
    # the default (firewall domain) is visible in logs/diagnostics.
    _ = _text(gen, "qualifying_suffix") or domain
    return args


def main():
    os.makedirs(RUN_DIR, exist_ok=True)
    gen, domain = load_settings()
    if gen is None or _text(gen, "enabled") != "1":
        # Not enabled: make sure nothing is running and exit cleanly.
        stopper.stop()
        return 0
    # Idempotent: stop any existing instance before (re)starting.
    stopper.stop()
    args = build_args(gen, domain)
    cmd = ["/usr/sbin/daemon", "-f", "-r", "-R", "5",
           "-p", PIDFILE, "-P", SUPERVISOR_PID,
           "/usr/local/bin/python3"] + args
    subprocess.run(cmd, check=False)
    # Seed existing leases/reservations so DNS is populated immediately rather than
    # waiting for the next DDNS event. Best-effort; never blocks the listener start.
    sync = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lease-sync.py")
    if os.path.exists(sync):
        subprocess.run(["/usr/local/bin/python3", sync], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
