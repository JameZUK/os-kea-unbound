# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Shared source of truth for "what Kea currently knows": active leases (control
socket, CSV fallback) + static reservations (generated config). Used by
lease-sync, audit, and clean so they agree on the desired record set.
"""

import csv
import json
import os
import time
import xml.etree.ElementTree as ET

from . import records as R
from . import kea_ctrl

CONFIG = "/conf/config.xml"
KEA4 = "/usr/local/etc/kea/kea-dhcp4.conf"
KEA6 = "/usr/local/etc/kea/kea-dhcp6.conf"
CSV4 = "/var/db/kea/kea-leases4.csv"
CSV6 = "/var/db/kea/kea-leases6.csv"


def _text(node, path, default=""):
    if node is None:
        return default
    el = node.find(path)
    return el.text.strip() if (el is not None and el.text) else default


def load_settings(config_path=CONFIG):
    """{'suffix': ...} when the plugin is enabled, else None."""
    try:
        root = ET.parse(config_path).getroot()
    except Exception:
        return None
    gen = root.find("./OPNsense/KeaUnbound/general")
    if gen is None or _text(gen, "enabled") != "1":
        return None
    return {"suffix": _text(gen, "qualifying_suffix") or _text(root.find("./system"), "domain", "")}


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def reservations(path, family):
    """(hostname, ip) from global + per-subnet reservations in the generated config."""
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
                        seen[addr] = row
                except (ValueError, KeyError):
                    continue
    except OSError:
        return []
    return [(r.get("hostname", ""), addr) for addr, r in seen.items() if r.get("hostname")]


def leases(family):
    """(hostname, ip) for active leases via control socket, CSV fallback."""
    cmd = "lease4-get-all" if family == "4" else "lease6-get-all"
    svc = "dhcp4" if family == "4" else "dhcp6"
    resp = kea_ctrl.send_command(cmd, service=svc)
    if isinstance(resp, dict) and resp.get("result") == 0:
        out = []
        for lease in (resp.get("arguments") or {}).get("leases") or []:
            if int(lease.get("state", 0) or 0) != 0:
                continue
            if family == "6" and lease.get("type") not in (None, "IA_NA"):
                continue
            host, addr = lease.get("hostname"), lease.get("ip-address")
            if host and addr:
                out.append((host, addr))
        return out
    return leases_csv(family)


def kea_reachable():
    """True if we can trust an empty desired set (Kea answered, or a CSV exists).

    Guards clean from wiping everything when Kea is merely unreachable."""
    for svc in ("dhcp4", "dhcp6"):
        resp = kea_ctrl.send_command("status-get", service=svc)
        if isinstance(resp, dict) and resp.get("result") == 0:
            return True
    return os.path.exists(CSV4) or os.path.exists(CSV6)


def reserved_ips():
    """Canonical set of all Kea-reserved IPs (v4 + v6)."""
    s = set()
    for path in (KEA4, KEA6):
        s |= R.reserved_ips_from_config(path)
    return s


def desired_records(suffix):
    """Forward A/AAAA + PTR for the *dynamic* leases Kea currently holds.

    DYNAMIC ONLY: reservations (and manual Host Overrides) are registered in DNS
    by OPNsense itself (host_entries.conf, forward + reverse). This plugin exists
    solely to add dynamic-lease DNS — which Kea + Unbound do not do natively — so
    we skip any lease whose address is a reservation and never touch an
    OPNsense-owned static name. Each dynamic lease still gets BOTH the forward
    (A/AAAA) and the reverse (PTR) record."""
    resv = reserved_ips()
    recs = []
    for fam in ("4", "6"):
        for host, ip in leases(fam):
            n = R._norm_ip(ip)
            if n is None or n in resv:
                continue  # reservation -> OPNsense's, not ours
            try:
                name = R.host_fqdn(host, suffix)
                if not name:
                    continue
                recs.append(R.Record(name, 3600, R.rrtype_for_ip(ip), ip))
                recs.append(R.Record(R.ptr_name(ip), 3600, "PTR", name))
            except (ValueError, KeyError):
                continue
    return recs
