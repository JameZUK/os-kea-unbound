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
from . import suffix as suffixmod

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
                    # the v6 memfile holds IA_NA, IA_TA and IA_PD rows; only IA_NA
                    # (lease_type 0) are host addresses. Never turn a delegated
                    # prefix (IA_PD) into a host AAAA/PTR. (Matches the socket path,
                    # which keeps only type IA_NA.)
                    if family == "6":
                        lt = (row.get("lease_type") or "0").strip()
                        if lt not in ("", "0", "IA_NA"):
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
    return [(r.get("hostname", ""), addr, r.get("subnet_id"))
            for addr, r in seen.items() if r.get("hostname")]


# A memfile CSV persists on disk after Kea stops, so its mere existence is not
# evidence Kea is current. Trust it as a lease source only if it was written
# recently (Kea rewrites it on lease changes / LFC while running).
CSV_MAX_AGE = 1800  # seconds


def _csv_fresh(family):
    path = CSV4 if family == "4" else CSV6
    try:
        delta = time.time() - os.path.getmtime(path)
    except OSError:
        return False
    return 0 <= delta < CSV_MAX_AGE  # a future mtime (clock skew) is not "fresh"


def _family_leases(family):
    """One lease query for a family -> (leases, source_ok).

    source_ok is True only when the list is AUTHORITATIVE: a successful
    control-socket reply, or (socket down) a CSV that exists and is fresh. Because a
    SINGLE fetch yields both the list and the flag, a caller can never confirm a
    family from one query while reading records from a different (divergent) one."""
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
                out.append((host, addr, lease.get("subnet-id")))
        return out, True
    if _csv_fresh(family):
        return leases_csv(family), True
    return [], False


def leases(family):
    """(hostname, ip, subnet_id) for active leases via control socket, fresh-CSV
    fallback. subnet_id maps a lease to its per-subnet qualifying suffix (issue #17)
    and may be None when the source doesn't report it."""
    return _family_leases(family)[0]


def _suffix_map(family, global_suffix):
    """{subnet_id: qualifying_suffix} for a family, from the generated Kea config.
    Empty when the config is absent/unreadable -> callers fall back to the global."""
    path = KEA4 if family == "4" else KEA6
    cfg = _load_json(path) or {}
    root = cfg.get("Dhcp4" if family == "4" else "Dhcp6") or {}
    subnet_key = "subnet4" if family == "4" else "subnet6"
    return suffixmod.suffix_by_subnet_id(root, subnet_key, global_suffix)


def lease_source_ok(family):
    """True if we have an authoritative current lease list for this family this run."""
    return _family_leases(family)[1]


def kea_reachable():
    """True if at least one family has a trustworthy lease source right now.

    Guards clean from wiping everything when Kea is merely unreachable (a stale
    leftover CSV no longer counts — see lease_source_ok)."""
    return any(lease_source_ok(fam) for fam in ("4", "6"))


def clean_inputs():
    """For clean: per family, the set of current dynamic-lease IPs (normalised,
    reservations excluded) and whether that family's source was authoritative this
    run — all from a SINGLE lease query per family (no double-fetch / TOCTOU).
    Returns (live_ips_by_family, prunable_by_family)."""
    live = {"4": set(), "6": set()}
    prunable = {"4": False, "6": False}
    for fam in ("4", "6"):
        resv, resv_ok = _reserved_for_family(fam)
        leases_list, source_ok = _family_leases(fam)
        prunable[fam] = source_ok and resv_ok
        if not resv_ok:
            continue
        for _host, ip, _sid in leases_list:
            n = R._norm_ip(ip)
            if n is not None and n not in resv:
                live[fam].add(n)
    return live, prunable


def _reserved_for_family(fam):
    """(reserved IP set, readable) for one family's Kea config. readable is False
    only when the config exists but couldn't be parsed — the caller then skips that
    family rather than risk treating a reservation as a dynamic lease."""
    path = KEA4 if fam == "4" else KEA6
    try:
        return R.reserved_ips_from_config(path), True
    except R.ReservedConfigError:
        return set(), False


def desired_records(suffix):
    """Forward A/AAAA + PTR for the *dynamic* leases Kea currently holds.

    DYNAMIC ONLY: reservations (and manual Host Overrides) are registered in DNS
    by OPNsense itself (host_entries.conf, forward + reverse). This plugin exists
    solely to add dynamic-lease DNS — which Kea + Unbound do not do natively — so
    we skip any lease whose address is a reservation and never touch an
    OPNsense-owned static name. Each dynamic lease still gets BOTH the forward
    (A/AAAA) and the reverse (PTR) record.

    Reservations are read per family. If a family's Kea config is present but
    unreadable (e.g. mid-regeneration) we skip that whole family rather than risk
    classifying a reserved host as dynamic."""
    recs = []
    for fam in ("4", "6"):
        resv, ok = _reserved_for_family(fam)
        if not ok:
            continue  # config present but unreadable -> skip this family
        # Per-subnet qualifying suffix (issue #17): qualify each lease with its own
        # subnet's domain so the seeded name matches what the live DDNS path (Kea)
        # writes. Unknown/absent subnet-id falls back to the global suffix.
        smap = _suffix_map(fam, suffix)
        for host, ip, sid in leases(fam):
            n = R._norm_ip(ip)
            if n is None or n in resv:
                continue  # reservation -> OPNsense's, not ours
            try:
                sfx = suffix
                if sid is not None:
                    try:
                        sfx = smap.get(int(sid), suffix)
                    except (TypeError, ValueError):
                        sfx = suffix
                name = R.host_fqdn(host, sfx)
                if not name:
                    continue
                recs.append(R.Record(name, 3600, R.rrtype_for_ip(ip), ip))
                recs.append(R.Record(R.ptr_name(ip), 3600, "PTR", name))
            except (ValueError, KeyError):
                continue
    return recs
