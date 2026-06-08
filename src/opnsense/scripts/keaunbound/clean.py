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
HOST_ENTRIES = "/var/unbound/host_entries.conf"
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
    if not os.path.exists(INCLUDE_FILE):
        print("keaunbound: clean — nothing to do (no include file)")
        return 0
    desired_keys = {r.key() for r in kea_source.desired_records(settings["suffix"])}
    # Only prune records of a family whose lease source we could confirm THIS run.
    # If e.g. the dhcp4 socket is down and its CSV is stale, every v4 record would
    # otherwise look "stale" and get mass-evicted — leave that family alone.
    confirmed = {fam: kea_source.lease_source_ok(fam) for fam in ("4", "6")}

    def family_of(r):
        if r.rtype == "AAAA":
            return "6"
        if r.rtype == "A":
            return "4"
        if r.rtype == "PTR":
            return "6" if r.name.endswith(".ip6.arpa.") else "4"
        return None

    # Never prune a name OPNsense owns (manual Host Override or Kea reservation).
    # Those are static, not ours; removing one local_data_remove's the whole name
    # and evicts OPNsense's record from Unbound's runtime (this broke hostname
    # firewall aliases once). We only ever prune our own dynamic records.
    guard = R.StaticGuard(HOST_ENTRIES, [kea_source.KEA4, kea_source.KEA6])

    def owned(r):
        if r.rtype == "PTR":
            return guard.is_static_ptr(r.name) or guard.is_reserved_ptr(r.name)
        return guard.is_static_forward(r.name, r.rtype) or guard.is_reserved_addr(r.rdata)

    def is_stale(r):
        if r.key() in desired_keys or owned(r):
            return False
        fam = family_of(r)
        if fam is None or not confirmed.get(fam, False):
            return False  # family's lease source unconfirmed -> don't risk it
        return True

    # Anomaly guard: a steady-state clean prunes a handful. A huge prune means the
    # desired set was probably partial (e.g. the control socket answered while Kea
    # was reloading), so refuse rather than mass-evict still-valid records.
    def abort_if(actual, removed):
        return len(removed) > max(20, len(actual) // 2)

    zone = UnboundZone(include_file=INCLUDE_FILE, unbound_conf=UNBOUND_CONF,
                       logger=lambda level, msg: None)
    removed, aborted = zone.prune(is_stale, abort_if)
    if aborted:
        msg = ("clean aborted — %d records would be pruned (> half the file); "
               "desired set looks partial, refusing to prune" % len(removed))
        log(msg)
        print("keaunbound: " + msg)
        return 1
    if not removed:
        print("keaunbound: clean — no stale records")
        return 0
    log("removed %d stale record(s)" % len(removed))
    print("keaunbound: clean removed %d stale record(s)" % len(removed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
