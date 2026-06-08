# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Pure record helpers and the static-entry guard.

Intentionally free of any third-party dependency (no dnspython) so the core
logic is unit-testable off-box. The daemon wires these together with dnspython
for the wire protocol.
"""

import ipaddress
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
    Kea). Takes the first label, lowercases it, strips invalid chars, appends the
    suffix. Returns "" if there is no usable label.
    """
    label = (hostname or "").strip().lower().split(".")[0]
    label = "".join(c for c in label if c.isalnum() or c == "-")
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


class StaticGuard:
    """
    Records that OPNsense manages itself (Unbound Host Overrides / "Register DHCP
    Static Mappings") live in host_entries.conf and must never be touched. Forward
    and PTR are gated independently: a static PTR for an IP must not suppress an
    unrelated forward record, and vice versa (carried over from v3.8 issue #11).
    """

    def __init__(self, host_entries_path: str):
        self._fwd = set()   # (name, type)
        self._ptr = set()   # ptr name
        try:
            with open(host_entries_path) as fh:
                for rec in parse_local_data_lines(fh.read()):
                    if rec.rtype == "PTR":
                        self._ptr.add(rec.name)
                    else:
                        self._fwd.add((rec.name, rec.rtype))
        except OSError:
            pass  # no static entries / file absent

    def is_static_forward(self, name: str, rtype: str) -> bool:
        return (fqdn(name), rtype.upper()) in self._fwd

    def is_static_ptr(self, ptr: str) -> bool:
        return fqdn(ptr) in self._ptr
