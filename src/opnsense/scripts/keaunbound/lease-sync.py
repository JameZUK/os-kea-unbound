#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Phase 5 — static / initial sync.

Kea's DDNS only fires for NEW lease events, so existing leases and static
reservations would not be registered until they next renew (and Unbound's
runtime data is rebuilt from our include file on restart). This script seeds them:

  reservations -> read from the generated kea-dhcp{4,6}.conf (hostname + ip)
  active leases -> Kea control unix socket lease{4,6}-get-all (lease_cmds), with
                   the memfile CSV (/var/db/kea/kea-leases{4,6}.csv) as fallback

Each entry is registered in Unbound (runtime + persistence file) via the same
record engine the listener uses: forward A/AAAA + PTR, with the host_entries.conf
static guard and dual-stack preservation. No-op when the plugin is disabled.

Run by configd action `keaunbound sync`, and by start.py after the listener
launches. Additive (does not remove stale records — that is Phase 8 audit/clean).
"""

import csv
import os
import sys
import time
import xml.etree.ElementTree as ET

_SCRIPTS = os.environ.get("KEAUNBOUND_SCRIPTS", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _SCRIPTS)

from lib import records as R          # noqa: E402
from lib import kea_ctrl              # noqa: E402
from lib.unbound_io import UnboundZone  # noqa: E402

CONFIG = "/conf/config.xml"
KEA4 = "/usr/local/etc/kea/kea-dhcp4.conf"
KEA6 = "/usr/local/etc/kea/kea-dhcp6.conf"
CSV4 = "/var/db/kea/kea-leases4.csv"
CSV6 = "/var/db/kea/kea-leases6.csv"
INCLUDE_FILE = "/var/unbound/etc/keaunbound.conf"
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


def _text(node, path, default=""):
    if node is None:
        return default
    el = node.find(path)
    return el.text.strip() if (el is not None and el.text) else default


def load_settings():
    try:
        root = ET.parse(CONFIG).getroot()
    except Exception:
        return None
    gen = root.find("./OPNsense/KeaUnbound/general")
    if gen is None or _text(gen, "enabled") != "1":
        return None
    return {"suffix": _text(gen, "qualifying_suffix") or _text(root.find("./system"), "domain", "")}


def _load_json(path):
    import json
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def reservations(path, family):
    """(hostname, ip) pairs from global + per-subnet reservations in the config."""
    cfg = _load_json(path)
    root_key = "Dhcp4" if family == "4" else "Dhcp6"
    node = (cfg or {}).get(root_key) or {}
    subnet_key = "subnet4" if family == "4" else "subnet6"
    res_lists = [node.get("reservations") or []]
    for container in [node] + list(node.get("shared-networks") or []):
        for sn in (container.get(subnet_key) or []):
            res_lists.append(sn.get("reservations") or [])
    out = []
    for rl in res_lists:
        for r in rl:
            host = r.get("hostname")
            if not host:
                continue
            ips = []
            if family == "4":
                if r.get("ip-address"):
                    ips.append(r["ip-address"])
            else:
                ips += list(r.get("ip-addresses") or [])
                if r.get("ip-address"):
                    ips.append(r["ip-address"])
            for ip in ips:
                out.append((host, ip))
    return out


def leases(family):
    """(hostname, ip) pairs for active leases via control socket, CSV fallback."""
    cmd = "lease4-get-all" if family == "4" else "lease6-get-all"
    svc = "dhcp4" if family == "4" else "dhcp6"
    resp = kea_ctrl.send_command(cmd, service=svc)
    if isinstance(resp, dict) and resp.get("result") == 0:
        out = []
        for lease in (resp.get("arguments") or {}).get("leases") or []:
            if int(lease.get("state", 0) or 0) != 0:
                continue
            if family == "6" and lease.get("type") not in (None, "IA_NA"):
                continue  # skip prefix delegations
            host, addr = lease.get("hostname"), lease.get("ip-address")
            if host and addr:
                out.append((host, addr))
        return out
    return leases_csv(family)


def leases_csv(family):
    """Fallback: parse the append-only memfile CSV (newest row per address)."""
    path = CSV4 if family == "4" else CSV6
    if not os.path.exists(path):
        return []
    now = int(time.time())
    seen = {}
    try:
        with open(path) as f:
            for row in csv.DictReader(f):
                try:
                    if int(row.get("state", "0") or 0) != 0:
                        continue
                    exp = row.get("expire", "")
                    if exp and int(exp) <= now:
                        continue
                    addr = (row.get("address") or "").strip()
                    if addr:
                        seen[addr] = row  # append-only: last wins
                except (ValueError, KeyError):
                    continue
    except OSError:
        return []
    return [(r.get("hostname", ""), addr) for addr, r in seen.items() if r.get("hostname")]


def main():
    s = load_settings()
    if s is None:
        print("keaunbound: disabled — no lease sync")
        return 0
    zone = UnboundZone(include_file=INCLUDE_FILE, unbound_conf=UNBOUND_CONF,
                       logger=lambda level, msg: None)
    guard = R.StaticGuard(HOST_ENTRIES)
    entries = (reservations(KEA4, "4") + reservations(KEA6, "6")
               + leases("4") + leases("6"))
    count = 0
    for host, ip in entries:
        try:
            name = R.host_fqdn(host, s["suffix"])
            if not name:
                continue
            rtype = R.rrtype_for_ip(ip)
            if not guard.is_static_forward(name, rtype):
                zone.add(R.Record(name, 3600, rtype, ip))
            ptr = R.ptr_name(ip)
            if not guard.is_static_ptr(ptr):
                zone.add(R.Record(ptr, 3600, "PTR", name))
            count += 1
        except (ValueError, KeyError):
            continue
    log("registered %d lease/reservation entries" % count)
    print("keaunbound: lease-sync registered %d entries" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
