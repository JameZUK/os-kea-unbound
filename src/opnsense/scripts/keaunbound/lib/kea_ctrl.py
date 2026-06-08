# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Minimal Kea control client over the per-daemon unix command socket.

OPNsense configures dhcp4/dhcp6 with a unix control-socket and loads the
lease_cmds hook, so `lease4-get-all` / `lease6-get-all` work directly on the
socket — no Kea Control Agent (KCA) needs to be enabled. Returns the parsed
response dict, or None on any failure (callers fall back to the memfile CSV).
"""

import json
import os
import socket

SOCKETS = {
    "dhcp4": "/var/run/kea/kea4-ctrl-socket",
    "dhcp6": "/var/run/kea/kea6-ctrl-socket",
}


def send_command(command, service="dhcp4", arguments=None, timeout=5.0):
    path = SOCKETS.get(service)
    if not path or not os.path.exists(path):
        return None
    payload = {"command": command}
    if arguments is not None:
        payload["arguments"] = arguments
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(path)
            sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            chunks = []
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, ValueError):
        return None
