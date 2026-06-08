#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
kea-unbound-ddns.py — RFC 2136 stub listener for Kea -> Unbound DNS registration.

Listens on a loopback UDP port, receives DNS UPDATE packets from kea-dhcp-ddns
(optionally TSIG-authenticated), and applies them to Unbound via the hybrid
writer (runtime unbound-control + persistent include file).

This is the real-time path. Bulk/initial population from existing Kea leases is
handled separately by the sync scripts (Phase 5).

Do not run directly in production — it is supervised by daemon(8) via the
`keaunbound` configd service (start.py / stop.py).
"""

import argparse
import logging
import logging.handlers
import os
import signal
import socket
import sys

# Make lib/ importable whether installed (/usr/local/opnsense/scripts/keaunbound)
# or run from a source checkout (../opnsense/scripts/keaunbound relative to sbin).
_SCRIPTS = os.environ.get("KEAUNBOUND_SCRIPTS", "/usr/local/opnsense/scripts/keaunbound")
for _cand in (_SCRIPTS,
              os.path.join(os.path.dirname(__file__), "..", "opnsense", "scripts", "keaunbound")):
    if os.path.isdir(os.path.join(_cand, "lib")):
        sys.path.insert(0, os.path.abspath(_cand))
        break

from lib import records as R          # noqa: E402
from lib.unbound_io import UnboundZone  # noqa: E402

log = logging.getLogger("keaunbound")


class StaticGuardCache:
    """Reload the guard (host_entries.conf static records + Kea reservations) only
    when one of the source files changes."""

    def __init__(self, path, kea_paths=()):
        self.path = path
        self.kea_paths = tuple(kea_paths)
        self._sig = None
        self._guard = R.StaticGuard(path, self.kea_paths)

    def _signature(self):
        sig = []
        for p in (self.path,) + self.kea_paths:
            try:
                sig.append((p, os.path.getmtime(p)))
            except OSError:
                sig.append((p, None))
        return tuple(sig)

    def get(self):
        sig = self._signature()
        if sig != self._sig:
            self._guard = R.StaticGuard(self.path, self.kea_paths)
            self._sig = sig
        return self._guard


class Listener:
    def __init__(self, args):
        self.args = args
        self.zone = UnboundZone(
            include_file=args.include_file,
            unbound_conf=args.unbound_conf,
            logger=lambda level, msg: getattr(log, level, log.info)(msg),
        )
        self.guard = StaticGuardCache(args.host_entries, args.kea_conf)
        self.keyring = None
        self.keyname = None
        self.keyalgo = None
        if not args.no_tsig and args.tsig_secret:
            from lib import tsig
            self.keyring = tsig.build_keyring(args.tsig_name, args.tsig_secret)
            self.keyname = args.tsig_name if args.tsig_name.endswith(".") else args.tsig_name + "."
            self.keyalgo = tsig.algorithm_name(args.tsig_algorithm)
        self._running = True

    # ---- record operations -----------------------------------------------
    def _add(self, name, ttl, rtype, rdata):
        guard = self.guard.get()
        if rtype == "PTR":
            # Reservations + Host Overrides are OPNsense's (forward + reverse).
            # We register dynamic leases only, so never write — and thus never
            # later evict — a reserved or statically-owned reverse name.
            if guard.is_static_ptr(name) or guard.is_reserved_ptr(name):
                log.info("Skipped PTR add for %s (static/reserved)", name)
                return
            self.zone.add(R.Record(name, ttl, "PTR", rdata))
            return
        if rtype not in ("A", "AAAA"):
            # Ignore DHCID and any other auxiliary RRs Kea includes. We own the
            # zone in Unbound and only publish address + pointer records; writing
            # a DHCID at a name later drags it into a blanket remove that can wipe
            # a co-located static record (it shares the name).
            return
        # forward A/AAAA
        if guard.is_static_forward(name, rtype) or guard.is_reserved_addr(rdata):
            log.info("Skipped %s add for %s (static/reserved)", rtype, name)
            return
        if self.args.aggressive_cleanup:
            self.zone.remove_other_addresses(name, rtype, rdata)
        self.zone.add(R.Record(name, ttl, rtype, rdata))

    def _delete(self, name, rtype, rdata):
        guard = self.guard.get()
        if rtype == "PTR":
            # Never delete a reverse record OPNsense owns statically, nor one for
            # a reserved IP (permanent mapping — guards the host_entries.conf
            # regeneration race where a reservation isn't in that file yet).
            if guard.is_static_ptr(name) or guard.is_reserved_ptr(name):
                return
            self.zone.remove(name, "PTR", rdata)
            return
        if rtype in ("A", "AAAA"):
            if guard.is_static_forward(name, rtype) or (rdata and guard.is_reserved_addr(rdata)):
                return
            self.zone.remove(name, rtype, rdata)
        elif rtype == "ANY":
            # Blanket "delete all RRsets at this name". unbound-control
            # local_data_remove drops EVERY type at the name, so:
            #  * never touch a name holding a static OPNsense record (forward or
            #    reverse) — that clobbered reserved hosts' records; and
            #  * for a FORWARD name, never honour it at all: A and AAAA there are
            #    owned by the separate kea-dhcp4 / kea-dhcp6 servers, and a v6
            #    removal's name-wide cleanup would wipe the v4 A (and vice versa).
            #    Kea always issues the specific A/AAAA delete first, so those handle
            #    real removal; ignoring the blanket cleanup keeps us family-safe.
            #    A REVERSE name holds a single PTR, so the blanket delete is safe.
            if (guard.is_static_forward(name, "A")
                    or guard.is_static_forward(name, "AAAA")
                    or guard.is_static_ptr(name)
                    or guard.is_reserved_ptr(name)):
                return
            if R.is_reverse_name(name):
                self.zone.remove(name)
            else:
                log.info("Ignored name-wide delete for forward %s (family-safe)", name)

    # ---- packet handling --------------------------------------------------
    def handle(self, data, addr, sock):
        import dns.message
        import dns.rdatatype
        import dns.rcode

        try:
            msg = dns.message.from_wire(data, keyring=self.keyring)
        except Exception as exc:  # noqa: BLE001 - bad/forged/unverifiable packet, drop
            log.warning("Dropped packet from %s: %s", addr, exc)
            return

        # When TSIG is configured, require a verified TSIG. from_wire raises on a
        # bad/unknown key, but an UNSIGNED message parses fine — reject it here so
        # an unauthenticated sender can't inject records.
        if self.keyring is not None and not getattr(msg, "had_tsig", False):
            log.warning("Dropped unsigned UPDATE from %s (TSIG required)", addr)
            return

        # Acknowledge FIRST, then apply. We don't do RFC 2136 prerequisite-based
        # conflict resolution (we own the zone) and always reply NOERROR, so there
        # is nothing to learn from doing the work before replying — and replying
        # up front keeps kea-dhcp-ddns from timing out (DHCP_DDNS_*_TIMEOUT) while
        # the listener does file/unbound-control I/O under a burst.
        try:
            resp = dns.message.make_response(msg)
            resp.set_rcode(dns.rcode.NOERROR)
            sock.sendto(resp.to_wire(), addr)
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to send response to %s: %s", addr, exc)

        # RFC 2136 operation is carried in each RRset's `.deleting` (dnspython):
        #   None -> add; NONE -> delete a specific RR; ANY -> delete an RRset / all.
        for rrset in msg.authority:
            name = rrset.name.to_text()
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            if rrset.deleting is None:
                for rdata in rrset:
                    self._add(name, rrset.ttl, rtype, rdata.to_text())
            elif len(rrset) == 0:
                self._delete(name, rtype, None)
            else:
                for rdata in rrset:
                    self._delete(name, rtype, rdata.to_text())

    # ---- main loop --------------------------------------------------------
    def serve(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Absorb bursts: kea-dhcp-ddns can fire many NCRs back-to-back while we
        # apply the previous one, so widen the receive buffer to avoid drops.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        except OSError:
            pass
        sock.bind((self.args.bind, self.args.port))
        sock.settimeout(1.0)
        log.info("Listening on %s:%d (tsig=%s)", self.args.bind, self.args.port,
                 "on" if self.keyring else "off")
        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._running:
                    log.error("recv error: %s", exc)
                continue
            self.handle(data, addr, sock)
        sock.close()
        log.info("Listener stopped")

    def stop(self, *_):
        self._running = False


def parse_args(argv):
    p = argparse.ArgumentParser(description="Kea -> Unbound DDNS listener")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=53535)
    p.add_argument("--unbound-conf", default="/var/unbound/unbound.conf")
    p.add_argument("--host-entries", default="/var/unbound/host_entries.conf")
    p.add_argument("--include-file", default="/usr/local/etc/unbound.opnsense.d/keaunbound.conf")
    p.add_argument("--kea-conf", action="append",
                   default=["/usr/local/etc/kea/kea-dhcp4.conf",
                            "/usr/local/etc/kea/kea-dhcp6.conf"],
                   help="Kea generated config(s) to read reservations from "
                        "(protect reserved hosts' records from deletion)")
    p.add_argument("--tsig-name", default="keaunbound")
    p.add_argument("--tsig-secret", default="")
    p.add_argument("--tsig-algorithm", default="hmac-sha256")
    p.add_argument("--no-tsig", action="store_true")
    p.add_argument("--aggressive-cleanup", action="store_true")
    p.add_argument("--log-file", default="/var/log/keaunbound/keaunbound.log")
    p.add_argument("--foreground", action="store_true")
    return p.parse_args(argv)


def setup_logging(log_file, foreground):
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    if foreground:
        h = logging.StreamHandler()
    else:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        h = logging.handlers.WatchedFileHandler(log_file)
    h.setFormatter(fmt)
    log.addHandler(h)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    setup_logging(args.log_file, args.foreground)
    listener = Listener(args)
    signal.signal(signal.SIGTERM, listener.stop)
    signal.signal(signal.SIGINT, listener.stop)
    listener.serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
