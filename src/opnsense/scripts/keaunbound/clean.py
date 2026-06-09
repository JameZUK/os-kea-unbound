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


def family_of(rec):
    """'4' or '6' for a record, by type and (for PTR) the reverse zone; None if
    neither. Used to scope pruning to families we could confirm."""
    if rec.rtype == "AAAA":
        return "6"
    if rec.rtype == "A":
        return "4"
    if rec.rtype == "PTR":
        return "6" if rec.name.endswith(".ip6.arpa.") else "4"
    return None


def is_stale_record(rec, live_by_fam, live_ptr, prunable, owned):
    """A dynamic record is stale iff its IP is no longer a live dynamic lease for
    its (confirmed) family. This is keyed on the ADDRESS, not the name, so a record
    the listener wrote under a name the sync path would reconstruct differently is
    never falsely pruned. Returns False (keep) when:
      * the record is OPNsense-owned (static / reservation),
      * its family wasn't confirmed prunable this run, or
      * its family currently has zero live leases (the "everything vanished"
        signature — leave it; the listener handles real expiries in real time)."""
    if owned(rec):
        return False
    fam = family_of(rec)
    if not fam or not prunable.get(fam, False):
        return False
    if not live_by_fam.get(fam):
        # Deliberate tradeoff: when a confirmed family reports ZERO live leases we
        # keep its records rather than prune. A `result==0` reply with an empty (or
        # partial) lease array is indistinguishable from a transient mid-reload, and
        # wiping live records on a transient is the original outage class (small
        # sites slip under the abort_if floor). Orphaning records for a genuinely
        # departed family is benign — they have TTLs and the listener removes them in
        # real time on the next lease event for that family. So we err toward keep.
        return False
    if rec.rtype in ("A", "AAAA"):
        return R._norm_ip(rec.rdata) not in live_by_fam.get(fam, set())
    if rec.rtype == "PTR":
        return rec.name not in live_ptr
    return False


def main():
    settings = kea_source.load_settings()
    if settings is None:
        print("keaunbound: disabled — no clean")
        return 0
    # ONE lease query per family yields both the current dynamic-lease IPs and the
    # per-family "authoritative" flag — no double-fetch / TOCTOU between the desired
    # set and the confirmation.
    live, prunable = kea_source.clean_inputs()
    if not any(prunable.values()):
        msg = "clean aborted — no Kea lease source confirmed; refusing to prune"
        log(msg)
        print("keaunbound: " + msg)
        return 1
    if not os.path.exists(INCLUDE_FILE):
        print("keaunbound: clean — nothing to do (no include file)")
        return 0

    # Never prune a name OPNsense owns (manual Host Override or Kea reservation).
    # Those are static, not ours; removing one local_data_remove's the whole name
    # and evicts OPNsense's record from Unbound's runtime (this broke hostname
    # firewall aliases once). We only ever prune our own dynamic records.
    guard = R.StaticGuard(HOST_ENTRIES, [kea_source.KEA4, kea_source.KEA6])

    def owned(r):
        if r.rtype == "PTR":
            return guard.is_static_ptr(r.name) or guard.is_reserved_ptr(r.name)
        return guard.is_static_forward(r.name, r.rtype) or guard.is_reserved_addr(r.rdata)

    # PTR names for every live IP, so reverse records are matched by address too.
    live_ptr = set()
    for ip in live["4"] | live["6"]:
        try:
            live_ptr.add(R.ptr_name(ip))
        except ValueError:
            pass

    def is_stale(r):
        return is_stale_record(r, live, live_ptr, prunable, owned)

    # Anomaly guard: a steady-state clean prunes a handful. A huge prune means the
    # lease list was probably partial (socket answered mid-reload), so refuse rather
    # than mass-evict. Measure against the records we'd actually consider (prunable
    # families only) so a large OTHER family can't dilute the ratio.
    def abort_if(actual, removed):
        universe = sum(1 for r in actual if prunable.get(family_of(r), False))
        limit = max(20, universe // 2)
        return len(removed) > limit

    # static_provider re-asserts a co-located OPNsense static record into the running
    # zone after prune's blanket local_data_remove, so pruning a stale dynamic record
    # at a name that also holds a static one (a forward AAAA, or a reserved PTR) can't
    # evict the static from runtime.
    zone = UnboundZone(include_file=INCLUDE_FILE, unbound_conf=UNBOUND_CONF,
                       logger=lambda level, msg: None,
                       static_provider=lambda name: guard.static_records(name))
    removed, aborted = zone.prune(is_stale, abort_if)
    if aborted:
        msg = ("clean aborted — %d records would be pruned (exceeds the prune "
               "safety threshold); desired set looks partial, refusing to prune"
               % len(removed))
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
