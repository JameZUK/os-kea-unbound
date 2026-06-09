#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Phase 5 — static / initial sync.

Kea's DDNS only fires for NEW lease events, so existing leases and static
reservations would not be registered until they next renew. This seeds them into
Unbound (runtime + persistence file) via the same record engine the listener
uses (host_entries static guard, dual-stack preservation, atomic file). No-op
when disabled. Additive (stale-record removal is handled by clean.py).

Run by configd action `keaunbound sync` and by start.py after the listener starts.
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
            f.write("%s [INFO] lease-sync: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def main():
    settings = kea_source.load_settings()
    if settings is None:
        print("keaunbound: disabled — no lease sync")
        return 0
    # Guard on host_entries.conf AND Kea reservations so we never seed (or later
    # touch) an OPNsense-owned static/reserved name. desired_records is already
    # dynamic-only; this is defence in depth for the host_entries case.
    guard = R.StaticGuard(HOST_ENTRIES, [kea_source.KEA4, kea_source.KEA6])
    # static_provider re-asserts a co-located OPNsense static record (a forward AAAA
    # or a reverse PTR) into the running zone after the reconcile's blanket
    # local_data_remove, so seeding a dynamic record for the same name can't evict it.
    zone = UnboundZone(include_file=INCLUDE_FILE, unbound_conf=UNBOUND_CONF,
                       logger=lambda level, msg: None,
                       static_provider=lambda name: guard.static_records(name))
    count = 0
    for rec in kea_source.desired_records(settings["suffix"]):
        if rec.rtype == "PTR":
            if guard.is_static_ptr(rec.name) or guard.is_reserved_ptr(rec.name):
                continue
        elif guard.is_static_forward(rec.name, rec.rtype) or guard.is_reserved_addr(rec.rdata):
            continue
        if zone.add(rec):
            count += 1
    log("registered %d records" % count)
    print("keaunbound: lease-sync registered %d records" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
