# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Pure record helpers and the static-entry guard.

Intentionally free of any third-party dependency (no dnspython) so the core
logic is unit-testable off-box. The daemon wires these together with dnspython
for the wire protocol.
"""

import ipaddress
import json
import re


def fqdn(name: str) -> str:
    """Normalise a DNS name to a lowercase absolute form (single trailing dot)."""
    name = (name or "").strip().lower()
    if not name:
        return ""
    return name if name.endswith(".") else name + "."


def rrtype_for_ip(ip: str) -> str:
    """Return 'A' or 'AAAA' for an address string."""
    return "AAAA" if ipaddress.ip_address(ip).version == 6 else "A"


def host_fqdn(hostname: str, suffix: str) -> str:
    """
    Build an absolute FQDN from a (possibly bare) DHCP hostname and a qualifying
    suffix, used by the static-sync path (the DDNS path gets ready-made FQDNs from
    Kea). Returns "" if there is no usable label.

    A multi-label hostname is already qualified (Kea and clients send FQDNs), so it
    is used verbatim — this is what the live DDNS path writes, so the sync/clean
    "desired" name matches the listener's name instead of diverging.
    """
    raw = (hostname or "").strip().lower().rstrip(".")
    if not raw:
        return ""

    # Keep only the chars Kea would have kept so this matches the name the live DDNS
    # path writes: ASCII letters/digits/hyphen and underscore (common in DHCP client
    # names, preserved by Kea); drop the rest (non-ASCII would be punycoded on the
    # wire and can't be reconstructed here). Crucially this also strips a stray '"' or
    # whitespace from an unsanitised lease/reservation hostname — writing those
    # verbatim would corrupt the quoted local-data line and the unbound-control input.
    def _san(part):
        return "".join(c for c in part if (c.isascii() and c.isalnum()) or c in "-_")

    if "." in raw:
        # Already-qualified (multi-label) name: sanitise EACH label the same way as a
        # single label. Normal names are unchanged (so the sync/clean "desired" name
        # still matches the live path); a label emptied by sanitisation means the name
        # isn't usable, so drop it entirely.
        labels = [_san(p) for p in raw.split(".")]
        if any(not lab for lab in labels):
            return ""
        return fqdn(".".join(labels))
    label = _san(raw)
    if not label:
        return ""
    suffix = (suffix or "").strip().strip(".")
    return fqdn(label + "." + suffix) if suffix else fqdn(label)


def ptr_name(ip: str) -> str:
    """Reverse-pointer name (absolute) for an IPv4 or IPv6 address."""
    return ipaddress.ip_address(ip).reverse_pointer + "."


def is_reverse_name(name: str) -> bool:
    n = fqdn(name)
    return n.endswith(".in-addr.arpa.") or n.endswith(".ip6.arpa.")


class Record:
    """A single local-data record: name + ttl + type + rdata (all normalised)."""

    __slots__ = ("name", "ttl", "rtype", "rdata")

    def __init__(self, name: str, ttl: int, rtype: str, rdata: str):
        self.name = fqdn(name)
        self.ttl = int(ttl)
        self.rtype = rtype.upper()
        # forward rdata (IPs) are case-insensitive; PTR target is a name.
        self.rdata = rdata.strip()
        if self.rtype == "PTR":
            self.rdata = fqdn(self.rdata)
        else:
            self.rdata = self.rdata.lower()

    def key(self):
        """Identity for dedupe: name + type + rdata (ttl excluded)."""
        return (self.name, self.rtype, self.rdata)

    def local_data_line(self) -> str:
        """Line for the Unbound include file."""
        return 'local-data: "%s %d IN %s %s"' % (self.name, self.ttl, self.rtype, self.rdata)

    def control_args(self):
        """Args for `unbound-control local_data ...` (the trailing data string)."""
        return ["%s %d IN %s %s" % (self.name, self.ttl, self.rtype, self.rdata)]

    def __eq__(self, other):
        return isinstance(other, Record) and self.key() == other.key()

    def __hash__(self):
        return hash(self.key())

    def __repr__(self):
        return "Record(%r)" % (self.local_data_line(),)


_LD_RE = re.compile(
    r'^\s*local-data:\s*"(?P<name>\S+)\s+(?:(?P<ttl>\d+)\s+)?IN\s+(?P<type>\S+)\s+(?P<rdata>.+?)"\s*$',
    re.IGNORECASE,
)
_LDPTR_RE = re.compile(
    r'^\s*local-data-ptr:\s*"(?P<ip>\S+)\s+(?:(?P<ttl>\d+)\s+)?(?P<target>\S+)"\s*$',
    re.IGNORECASE,
)


def parse_local_data_lines(text: str):
    """Parse local-data / local-data-ptr lines into Record objects."""
    out = []
    for line in text.splitlines():
        m = _LD_RE.match(line)
        if m:
            out.append(Record(m.group("name"), int(m.group("ttl") or 3600),
                              m.group("type"), m.group("rdata")))
            continue
        m = _LDPTR_RE.match(line)
        if m:
            out.append(Record(ptr_name(m.group("ip")), int(m.group("ttl") or 3600),
                              "PTR", m.group("target")))
    return out


def _norm_ip(value):
    """Canonical string form of an IP, or None if it isn't one.

    Strips an IPv6 zone id (``fe80::1%igb0``) and collapses an IPv4-mapped IPv6
    address (``::ffff:192.0.2.5``) to its v4 form, so the same host written by Kea
    and stored in a reservation compares equal regardless of which form was used.
    """
    try:
        s = (value or "").strip()
        if "%" in s:                     # drop IPv6 scope/zone id before parsing
            s = s.split("%", 1)[0]
        addr = ipaddress.ip_address(s)
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            addr = mapped
        return str(addr)
    except (ValueError, AttributeError):
        return None


class ReservedConfigError(Exception):
    """A Kea config exists but could not be read/parsed (e.g. mid-regeneration).

    Distinct from "no config present" so callers can refuse to treat reservations
    as dynamic when the source is merely momentarily unreadable."""


def reserved_ips_from_config(path: str):
    """Set of reserved IPs (canonicalised) from a generated Kea dhcp4/6 config.

    Covers global, per-subnet and shared-network reservations. Used to protect a
    reserved host's records from DDNS deletes even before OPNsense has (re)written
    host_entries.conf — a reservation is a permanent host<->IP mapping.

    Returns an empty set when the config simply does not exist (that family has no
    reservations); raises ReservedConfigError when the file is present but cannot be
    parsed, so the caller doesn't mistake "couldn't read" for "none reserved"."""
    out = set()
    try:
        with open(path) as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        return out
    except (OSError, ValueError) as exc:
        raise ReservedConfigError(path) from exc
    if "Dhcp4" in cfg:
        root, subkey = cfg["Dhcp4"], "subnet4"
    elif "Dhcp6" in cfg:
        root, subkey = cfg["Dhcp6"], "subnet6"
    else:
        return out
    res_lists = [root.get("reservations") or []]
    for container in [root] + list(root.get("shared-networks") or []):
        for sn in (container.get(subkey) or []):
            res_lists.append(sn.get("reservations") or [])
    for rl in res_lists:
        for r in rl:
            ips = list(r.get("ip-addresses") or [])
            if r.get("ip-address"):
                ips.append(r["ip-address"])
            for ip in ips:
                n = _norm_ip(ip)
                if n:
                    out.add(n)
    return out


class StaticGuard:
    """
    Records that OPNsense manages itself (Unbound Host Overrides / "Register DHCP
    Static Mappings") live in host_entries.conf and must never be touched. Forward
    and PTR are gated independently: a static PTR for an IP must not suppress an
    unrelated forward record, and vice versa (carried over from v3.8 issue #11).
    """

    def __init__(self, host_entries_path: str, kea_paths=()):
        self._fwd = set()        # (name, type) from host_entries.conf
        self._fwd_recs = {}      # name -> [Record] (full static forward records)
        self._ptr = set()        # ptr name from host_entries.conf
        self._ptr_recs = {}      # ptr name -> [Record] (full static PTR records)
        self._reserved = set()   # canonical reserved IPs (Kea reservations)
        self._reserved_ptr = set()  # ptr names for reserved IPs
        try:
            with open(host_entries_path) as fh:
                for rec in parse_local_data_lines(fh.read()):
                    if rec.rtype == "PTR":
                        self._ptr.add(rec.name)
                        self._ptr_recs.setdefault(rec.name, []).append(rec)
                    else:
                        self._fwd.add((rec.name, rec.rtype))
                        self._fwd_recs.setdefault(rec.name, []).append(rec)
        except OSError:
            pass  # no static entries / file absent
        for path in kea_paths:
            try:
                ips = reserved_ips_from_config(path)
            except ReservedConfigError:
                # secondary guard only (host_entries.conf is primary); tolerate a
                # momentarily-unreadable Kea config rather than failing the guard.
                ips = set()
            for ip in ips:
                self._reserved.add(ip)
                try:
                    self._reserved_ptr.add(ptr_name(ip))
                except ValueError:
                    pass

    def is_static_forward(self, name: str, rtype: str) -> bool:
        return (fqdn(name), rtype.upper()) in self._fwd

    def forward_records(self, name: str):
        """Full static forward Records (A/AAAA from host_entries.conf) at this name.

        Lets the runtime reconcile re-assert a co-located static record of a
        DIFFERENT family than the dynamic one being written — otherwise the blanket
        local_data_remove during reconcile evicts e.g. a static AAAA from the running
        resolver when we write a dynamic A for the same host (until the next Unbound
        reload). These records are never in our include file, so only the guard knows
        them."""
        return list(self._fwd_recs.get(fqdn(name), []))

    def static_records(self, name: str):
        """All OPNsense-owned static records (forward A/AAAA OR reverse PTR) at this
        name, for the runtime reconcile to re-assert after its blanket
        local_data_remove. A name is either forward or reverse, so at most one side is
        non-empty. Extends forward_records to the reverse side: aggressive cleanup and
        clean reconcile a stale IP's PTR name, and a co-located static/reserved PTR
        (e.g. an address that has since become a reservation) must not be evicted from
        the running resolver."""
        n = fqdn(name)
        return list(self._fwd_recs.get(n, [])) + list(self._ptr_recs.get(n, []))

    def is_static_ptr(self, ptr: str) -> bool:
        return fqdn(ptr) in self._ptr

    def is_reserved_addr(self, rdata: str) -> bool:
        """True if rdata is the IP of a Kea reservation (permanent host<->IP)."""
        n = _norm_ip(rdata)
        return n is not None and n in self._reserved

    def is_reserved_ptr(self, ptr: str) -> bool:
        """True if the reverse name belongs to a reserved IP."""
        return fqdn(ptr) in self._reserved_ptr
