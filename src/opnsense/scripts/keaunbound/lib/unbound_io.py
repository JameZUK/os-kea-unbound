# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Hybrid Unbound writer: keeps records both in the running resolver (runtime, via
unbound-control, for immediate effect) AND in an include file (for persistence
across Unbound restarts).

The include file lives in OPNsense's unbound custom-include SOURCE dir
(/usr/local/etc/unbound.opnsense.d/keaunbound.conf). On every unbound start,
start.sh wipes the chroot /var/unbound/etc/ and re-copies *.conf from that source
dir into it; the generated unbound.conf then pulls them in via
`include: /var/unbound/etc/*.conf`. Writing the source (not the chroot copy, which
is rebuilt each start) is what makes records survive Unbound restarts.

The file is the source of truth. After any change we rewrite it atomically and
then reconcile the running zone for the affected name: local_data_remove (which
wipes ALL records for a name) followed by re-adding every remaining record for
that name. This makes dual-stack sibling preservation fall out for free — delete
the A and the AAAA is simply re-added from the file.

unbound-control is injected as a runner callable so the file logic is testable
without a running Unbound.
"""

import os
import subprocess
import tempfile
import fcntl

from . import records as rec_mod


def default_runner(unbound_conf):
    """Return a runner(args_list, input=None) -> (rc, output) bound to a config file.

    `input` feeds stdin, used for the batched `local_datas`/`local_datas_remove`
    commands (one process for many records instead of one per record)."""
    def _run(args, input=None):
        cmd = ["unbound-control", "-c", unbound_conf] + list(args)
        try:
            out = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=15)
            return out.returncode, (out.stdout + out.stderr)
        except Exception as exc:  # noqa: BLE001 - best effort, runtime is non-fatal
            return 1, str(exc)
    return _run


class UnboundZone:
    def __init__(self, include_file, unbound_conf="/var/unbound/unbound.conf",
                 runner=None, lock_path=None, logger=None):
        self.include_file = include_file
        self.unbound_conf = unbound_conf
        self.runner = runner if runner is not None else default_runner(unbound_conf)
        self.lock_path = lock_path or (include_file + ".lock")
        self.logger = logger or (lambda level, msg: None)
        self._records = []  # list[Record]
        self._load()

    # ---- persistence ------------------------------------------------------
    def _load(self):
        try:
            with open(self.include_file) as fh:
                self._records = rec_mod.parse_local_data_lines(fh.read())
        except OSError:
            self._records = []

    def _write_file(self):
        header = "# Managed by os-kea-unbound (DDNS). Do not edit by hand.\n"
        body = "\n".join(r.local_data_line() for r in self._records)
        data = header + body + ("\n" if body else "")
        d = os.path.dirname(self.include_file) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(data)
            os.replace(tmp, self.include_file)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    # ---- runtime ----------------------------------------------------------
    def _records_for(self, name):
        name = rec_mod.fqdn(name)
        return [r for r in self._records if r.name == name]

    def _reconcile_runtime(self, name):
        """Remove the name from the running zone, then re-add all current records.

        Uses one `local_data_remove` + one batched `local_datas` (records on
        stdin) so a name is reconciled with at most two unbound-control spawns,
        regardless of how many records it has."""
        name = rec_mod.fqdn(name)
        rc, out = self.runner(["local_data_remove", name])
        if rc != 0:
            self.logger("error", "local_data_remove %s failed: %s" % (name, out.strip()))
        recs = self._records_for(name)
        if recs:
            data = "".join(r.control_args()[0] + "\n" for r in recs)
            rc, out = self.runner(["local_datas"], input=data)
            if rc != 0:
                self.logger("error", "local_datas for %s failed: %s" % (name, out.strip()))

    # ---- public API -------------------------------------------------------
    def add(self, record):
        """Add/replace a record; returns True if anything changed."""
        with _Lock(self.lock_path):
            self._load()
            key = record.key()
            existing = next((r for r in self._records if r.key() == key), None)
            if existing is not None and existing.ttl == record.ttl:
                return False
            self._records = [r for r in self._records if r.key() != key]
            self._records.append(record)
            self._write_file()
            self._reconcile_runtime(record.name)
            self.logger("info", "Added %s" % record.local_data_line())
            return True

    def remove(self, name, rtype=None, rdata=None):
        """Remove matching records for a name (optionally by type/rdata)."""
        with _Lock(self.lock_path):
            self._load()
            name = rec_mod.fqdn(name)
            before = len(self._records)

            def matches(r):
                if r.name != name:
                    return False
                if rtype is not None and r.rtype != rtype.upper():
                    return False
                if rdata is not None and r.rdata != rec_mod.Record(name, 0, rtype or "A", rdata).rdata:
                    return False
                return True

            removed = [r for r in self._records if matches(r)]
            if not removed:
                return False
            self._records = [r for r in self._records if not matches(r)]
            self._write_file()
            self._reconcile_runtime(name)
            for r in removed:
                self.logger("info", "Removed %s" % r.local_data_line())
            return True

    def remove_other_addresses(self, name, rtype, keep_rdata):
        """
        Aggressive cleanup: drop other forward records of the same type for a host
        (and their PTRs) when the host moves to a new address. Returns removed IPs.
        """
        with _Lock(self.lock_path):
            self._load()
            name = rec_mod.fqdn(name)
            keep = rec_mod.Record(name, 0, rtype, keep_rdata).rdata
            stale = [r for r in self._records
                     if r.name == name and r.rtype == rtype.upper() and r.rdata != keep]
            if not stale:
                return []
            stale_ips = [r.rdata for r in stale]
            stale_keys = {r.key() for r in stale}
            ptr_names = {rec_mod.ptr_name(ip) for ip in stale_ips}
            self._records = [r for r in self._records
                             if r.key() not in stale_keys and r.name not in ptr_names]
            self._write_file()
            self._reconcile_runtime(name)
            for ptr in ptr_names:
                self._reconcile_runtime(ptr)
            self.logger("info", "Cleaned stale %s for %s: %s" % (rtype, name, ", ".join(stale_ips)))
            return stale_ips


class _Lock:
    """flock-based mutual exclusion across the daemon and the sync scripts."""

    def __init__(self, path):
        self.path = path
        self._fh = None

    def __enter__(self):
        d = os.path.dirname(self.path) or "."
        os.makedirs(d, exist_ok=True)
        self._fh = open(self.path, "w")
        fcntl.flock(self._fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self._fh, fcntl.LOCK_UN)
        finally:
            self._fh.close()
