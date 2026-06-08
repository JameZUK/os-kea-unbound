#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Emit the DDNS records currently registered in Unbound (our include file) as a
JSON array, enriched with Kea lease/reservation detail where the address
matches. Consumed by the Records page (Api\\RecordsController) for a
searchable/sortable/filterable grid.

Output: a JSON list of objects, one per local-data record:
    id, name, type, value, ttl, scope (forward|reverse),
    hostname, hwaddr, subnet, source (lease|reservation|ddns), expires (epoch)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import records as R          # noqa: E402
from lib import kea_source, kea_ctrl  # noqa: E402

INCLUDE_FILE = "/usr/local/etc/unbound.opnsense.d/keaunbound.conf"


def _full_leases(family):
    """Full lease dicts (hw-address, cltt, valid-lft, ...) via the control socket."""
    cmd = "lease4-get-all" if family == "4" else "lease6-get-all"
    svc = "dhcp4" if family == "4" else "dhcp6"
    resp = kea_ctrl.send_command(cmd, service=svc)
    if isinstance(resp, dict) and resp.get("result") == 0:
        return (resp.get("arguments") or {}).get("leases") or []
    return []


def _enrichment_map():
    """Map both an address and its PTR name to {hostname, hwaddr, expires, source, subnet}.

    Reservations are seeded first; live leases override them (a lease is the
    current truth). Keying by PTR name as well lets us enrich PTR records
    directly without reversing the name.
    """
    m = {}

    def put(ip, info):
        try:
            m[ip] = info
            m[R.ptr_name(ip)] = info
        except (ValueError, KeyError):
            pass

    # static reservations (generated kea config) — no expiry, source=reservation
    for path, fam in ((kea_source.KEA4, "4"), (kea_source.KEA6, "6")):
        for host, ip in kea_source.reservations(path, fam):
            put(ip, {"hostname": host, "hwaddr": "", "expires": 0,
                     "source": "reservation", "subnet": ""})

    # active leases (live) override reservations
    for fam in ("4", "6"):
        for lease in _full_leases(fam):
            try:
                if int(lease.get("state", 0) or 0) != 0:
                    continue
            except (ValueError, TypeError):
                continue
            if fam == "6" and lease.get("type") not in (None, "IA_NA"):
                continue
            ip = lease.get("ip-address")
            if not ip:
                continue
            try:
                cltt = int(lease.get("cltt", 0) or 0)
                vlft = int(lease.get("valid-lft", 0) or 0)
            except (ValueError, TypeError):
                cltt = vlft = 0
            put(ip, {
                "hostname": lease.get("hostname", "") or "",
                "hwaddr": lease.get("hw-address") or lease.get("duid") or "",
                "expires": (cltt + vlft) if (cltt and vlft) else 0,
                "source": "lease",
                "subnet": str(lease.get("subnet-id", "") or ""),
            })
    return m


def main():
    rows = []
    if os.path.exists(INCLUDE_FILE):
        try:
            with open(INCLUDE_FILE) as fh:
                recs = R.parse_local_data_lines(fh.read())
        except OSError:
            recs = []
        try:
            emap = _enrichment_map()
        except Exception:
            emap = {}  # never let enrichment failure hide the records
        for i, rec in enumerate(recs):
            reverse = rec.rtype == "PTR"
            info = emap.get(rec.name if reverse else rec.rdata, {})
            rows.append({
                "id": i,
                "name": rec.name.rstrip("."),
                "type": rec.rtype,
                "value": rec.rdata.rstrip(".") if reverse else rec.rdata,
                "ttl": rec.ttl,
                "scope": "reverse" if reverse else "forward",
                "hostname": (info.get("hostname", "") or "").rstrip("."),
                "hwaddr": info.get("hwaddr", ""),
                "subnet": info.get("subnet", ""),
                "source": info.get("source") or "ddns",
                "expires": info.get("expires", 0),
            })
    print(json.dumps(rows))


if __name__ == "__main__":
    main()
