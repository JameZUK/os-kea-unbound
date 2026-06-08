#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Phase 8 — read-only audit. Compares the records we have in Unbound (the include
file) against what Kea currently knows (reservations + active leases) and reports
drift: stale (ours, but Kea no longer has it) and missing (Kea has it, not ours).
Emits JSON. Run by configd action `keaunbound audit`. Never modifies anything.
"""

import json
import os
import sys

_SCRIPTS = os.environ.get("KEAUNBOUND_SCRIPTS", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _SCRIPTS)

from lib import records as R      # noqa: E402
from lib import kea_source        # noqa: E402

INCLUDE_FILE = "/var/unbound/etc/keaunbound.conf"


def _actual():
    try:
        with open(INCLUDE_FILE) as f:
            return R.parse_local_data_lines(f.read())
    except OSError:
        return []


def main():
    settings = kea_source.load_settings()
    if settings is None:
        print(json.dumps({"enabled": False}))
        return 0
    desired = kea_source.desired_records(settings["suffix"])
    desired_keys = {r.key() for r in desired}
    actual = _actual()
    actual_keys = {r.key() for r in actual}
    stale = [r for r in actual if r.key() not in desired_keys]
    missing = [r for r in desired if r.key() not in actual_keys]
    print(json.dumps({
        "enabled": True,
        "kea_reachable": kea_source.kea_reachable(),
        "in_unbound": len(actual),
        "in_kea": len(desired),
        "stale": [r.local_data_line() for r in stale],
        "missing": [r.local_data_line() for r in missing],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
