# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Per-subnet DDNS qualifying-suffix resolution (issue #17).

A site with multiple VLANs wants each dynamic lease registered under *its* subnet's
domain, not one firewall-wide suffix. The per-subnet domain is taken from the
subnet's DHCP "Domain name" option (option 15), which OPNsense writes into the
generated Kea config as an `option-data` entry. When a subnet has no domain-name
option we fall back to the global suffix (plugin setting -> firewall domain), so
single-domain sites are unaffected.

Pure helpers (no I/O, no third-party deps) so both the kea_sync injector
(kea-config-sync.py) and the lease seeder (kea_source.py) share one resolution
rule and stay in lock-step.
"""


def norm(s):
    """Comparison form of a suffix: lowercase, no surrounding whitespace or dots.

    DNS suffixes are case-insensitive and the trailing dot is optional, so two
    suffixes are "the same zone" iff their norm() forms match."""
    return (s or "").strip().strip(".").lower()


def clean(s):
    """Storage form written into the Kea config: trimmed, no trailing dot, original
    case preserved (Kea lowercases on the wire; we keep the admin's spelling)."""
    return (s or "").strip().strip(".")


def domain_name_option(subnet):
    """The subnet's DHCP domain-name option value, or '' if it has none."""
    for opt in (subnet.get("option-data") or []):
        if opt.get("name") == "domain-name" and (opt.get("data") or "").strip():
            return opt["data"].strip()
    return ""


def subnet_suffix(subnet, global_suffix):
    """Resolved DDNS suffix for one subnet dict from the generated Kea config:
    its domain-name option if set, else the global suffix ('' if neither)."""
    return domain_name_option(subnet) or (global_suffix or "")


def iter_subnets(root, subnet_key):
    """Yield every subnet dict under a Dhcp4/Dhcp6 root, including those nested in
    shared-networks (mirrors how reservations are enumerated)."""
    for sn in (root.get(subnet_key) or []):
        yield sn
    for net in (root.get("shared-networks") or []):
        for sn in (net.get(subnet_key) or []):
            yield sn


def suffix_by_subnet_id(root, subnet_key, global_suffix):
    """{subnet_id(int): resolved_suffix} for one family. subnet-id is the key both
    the control socket and the memfile CSV report per lease, so the seeder can map a
    lease straight to its suffix."""
    out = {}
    for sn in iter_subnets(root, subnet_key):
        sid = sn.get("id")
        if sid is None:
            continue
        try:
            out[int(sid)] = subnet_suffix(sn, global_suffix)
        except (TypeError, ValueError):
            continue
    return out
