#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Phase 8 — prune stale records. Removes entries in our include file that Kea no
longer knows about (expired/released leases the listener missed, e.g. while it
was down). The listener handles deletes in real time; this is the on-demand
backstop. Run by configd action `keaunbound clean`.

Safety: aborts if Kea is unreachable, so a transient failure can never be read as
"nothing is desired" and wipe every record.
"""

import os
import sys
import time

_SCRIPTS = os.environ.get("KEAUNBOUND_SCRIPTS", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _SCRIPTS)

from lib import records as R          # noqa: E402
from lib import kea_source            # noqa: E402
from lib.unbound_io import UnboundZone  # noqa: E402

INCLUDE_FILE = "/usr/local/etc/unbound.opnsense.d/keaunbound.conf"
UNBOUND_CONF = "/var/unbound/unbound.conf"
LOG = "/var/log/keaunbound/keaunbound.log"


def log(msg):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write("%s [INFO] clean: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def main():
    settings = kea_source.load_settings()
    if settings is None:
        print("keaunbound: disabled — no clean")
        return 0
    if not kea_source.kea_reachable():
        msg = "clean aborted — Kea unreachable; refusing to prune"
        log(msg)
        print("keaunbound: " + msg)
        return 1
    try:
        with open(INCLUDE_FILE) as f:
            actual = R.parse_local_data_lines(f.read())
    except OSError:
        print("keaunbound: clean — nothing to do (no include file)")
        return 0
    desired_keys = {r.key() for r in kea_source.desired_records(settings["suffix"])}
    stale = [r for r in actual if r.key() not in desired_keys]
    if not stale:
        print("keaunbound: clean — no stale records")
        return 0
    zone = UnboundZone(include_file=INCLUDE_FILE, unbound_conf=UNBOUND_CONF,
                       logger=lambda level, msg: None)
    for r in stale:
        zone.remove(r.name, r.rtype, r.rdata)
    log("removed %d stale record(s)" % len(stale))
    print("keaunbound: clean removed %d stale record(s)" % len(stale))
    return 0


if __name__ == "__main__":
    sys.exit(main())
