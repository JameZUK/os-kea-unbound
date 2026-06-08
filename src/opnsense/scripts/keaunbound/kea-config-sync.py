#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
Phase 4 injector — runs as a `kea_sync` hook.

`pluginctl -c kea_sync` runs every plugin's kea_sync function in .inc filename
order. Kea's own `kea_configure_do` (kea.inc, sorts first) regenerates the daemon
configs from the model; this script (keaunbound.inc, sorts after) then injects the
DDNS settings that OPNsense's GUI cannot express globally — so Kea uses its native
DDNS pointed at our loopback listener, with no per-subnet config and no patching of
Kea's PHP/templates.

Safety (Phase 4.5):
  * Atomic: every file is written via os.replace (never a partial file).
  * Non-destructive: existing user-configured DDNS domains and TSIG keys in
    kea-dhcp-ddns.conf are PRESERVED — we add our catch-all alongside them (Kea
    picks the longest-suffix match, so a user's specific zone still goes to their
    server; everything else goes to our listener). We only strip a per-subnet
    "ddns-send-updates": false (Kea's "no DDNS" default) so subnets inherit our
    global true — never an explicit user value.
  * Alerted: every change is written to the plugin log.
  * Self-cleaning: a disabled plugin is a no-op, so the next Kea regeneration
    leaves a pristine config.
"""

import json
import os
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

CONFIG = "/conf/config.xml"
KEA4 = "/usr/local/etc/kea/kea-dhcp4.conf"
KEA6 = "/usr/local/etc/kea/kea-dhcp6.conf"
D2 = "/usr/local/etc/kea/kea-dhcp-ddns.conf"
LOG = "/var/log/keaunbound/keaunbound.log"

CATCHALL_FWD = "."
CATCHALL_REV = ("in-addr.arpa.", "ip6.arpa.")

KEA_ALGO = {
    "hmac-md5": "HMAC-MD5", "hmac-sha1": "HMAC-SHA1", "hmac-sha224": "HMAC-SHA224",
    "hmac-sha256": "HMAC-SHA256", "hmac-sha384": "HMAC-SHA384", "hmac-sha512": "HMAC-SHA512",
}


def log(msg):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write("%s [INFO] config-sync: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def _text(node, path, default=""):
    if node is None:
        return default
    el = node.find(path)
    return el.text.strip() if (el is not None and el.text) else default


def load_settings():
    """Return settings dict if the plugin is enabled, else None."""
    try:
        root = ET.parse(CONFIG).getroot()
    except Exception:
        return None
    gen = root.find("./OPNsense/KeaUnbound/general")
    if gen is None or _text(gen, "enabled") != "1":
        return None
    suffix = _text(gen, "qualifying_suffix") or _text(root.find("./system"), "domain", "")
    tsig_secret = _text(gen, "tsig_key_secret")
    return {
        "port": int(_text(gen, "listener_port", "53535") or 53535),
        "suffix": suffix,
        "tsig": _text(gen, "tsig_enabled", "1") == "1" and bool(tsig_secret),
        "tsig_name": (_text(gen, "tsig_key_name", "keaunbound") or "keaunbound"),
        "tsig_secret": tsig_secret,
        "tsig_algo": KEA_ALGO.get(_text(gen, "tsig_algorithm", "hmac-sha256"), "HMAC-SHA256"),
    }


def _write_atomic(path, data):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def patch_dhcp(path, root_key, s):
    cfg = _load_json(path)
    if not isinstance(cfg, dict) or not isinstance(cfg.get(root_key), dict):
        return False
    node = cfg[root_key]
    before = json.dumps(node, sort_keys=True)
    node["ddns-send-updates"] = True
    if s["suffix"]:
        node["ddns-qualifying-suffix"] = s["suffix"]
    node["ddns-replace-client-name"] = "when-not-present"
    node["ddns-generated-prefix"] = "host"
    # OPNsense emits a per-subnet "ddns-send-updates": false (no per-subnet DDNS
    # server is set), which would OVERRIDE our global true via Kea's subnet>global
    # inheritance. Strip ONLY that false default (never an explicit user true) so
    # those subnets inherit the global value.
    subnet_key = "subnet4" if root_key == "Dhcp4" else "subnet6"
    for container in [node] + list(node.get("shared-networks", []) or []):
        for sn in (container.get(subnet_key, []) or []):
            if sn.get("ddns-send-updates") is False:
                sn.pop("ddns-send-updates", None)
    if json.dumps(node, sort_keys=True) == before:
        return False
    _write_atomic(path, json.dumps(cfg, indent=2))
    return True


def patch_d2(path, s):
    cfg = _load_json(path)
    if not isinstance(cfg, dict) or not isinstance(cfg.get("DhcpDdns"), dict):
        return False
    d2 = cfg["DhcpDdns"]
    before = json.dumps(d2, sort_keys=True)
    keyname = (s["tsig_name"] + ".") if s["tsig"] else None
    our_server = {"ip-address": "127.0.0.1", "port": s["port"]}

    def catchall(name):
        dom = {"name": name, "dns-servers": [dict(our_server)]}
        if keyname:
            dom["key-name"] = keyname
        return dom

    # Forward: keep any user domains (name != "."), (re)add our catch-all ".".
    fwd = (d2.get("forward-ddns") or {}).get("ddns-domains") or []
    user_fwd = [d for d in fwd if d.get("name") != CATCHALL_FWD]
    if user_fwd:
        log("preserving %d user forward DDNS domain(s); adding catch-all" % len(user_fwd))
    d2["forward-ddns"] = {"ddns-domains": user_fwd + [catchall(CATCHALL_FWD)]}

    # Reverse: keep user domains, (re)add our in-addr.arpa./ip6.arpa. catch-alls.
    rev = (d2.get("reverse-ddns") or {}).get("ddns-domains") or []
    user_rev = [d for d in rev if d.get("name") not in CATCHALL_REV]
    if user_rev:
        log("preserving %d user reverse DDNS domain(s); adding catch-all" % len(user_rev))
    d2["reverse-ddns"] = {"ddns-domains": user_rev + [catchall(n) for n in CATCHALL_REV]}

    # TSIG: keep user keys (different name), (re)add ours.
    keys = d2.get("tsig-keys") or []
    if keyname:
        keys = [k for k in keys if k.get("name") != keyname]
        keys.append({"name": keyname, "algorithm": s["tsig_algo"], "secret": s["tsig_secret"]})
    d2["tsig-keys"] = keys

    if json.dumps(d2, sort_keys=True) == before:
        return False
    _write_atomic(path, json.dumps(cfg, indent=2))
    return True


def main():
    s = load_settings()
    if s is None:
        print("keaunbound: disabled/unreadable — no DDNS injection")
        return 0
    changed = []
    if patch_dhcp(KEA4, "Dhcp4", s):
        changed.append("dhcp4")
    if patch_dhcp(KEA6, "Dhcp6", s):
        changed.append("dhcp6")
    if patch_d2(D2, s):
        changed.append("ddns")
    msg = "DDNS injection -> " + (", ".join(changed) if changed else "(no change)")
    print("keaunbound: " + msg)
    if changed:
        log("%s (listener 127.0.0.1:%d, tsig=%s)" % (msg, s["port"], "on" if s["tsig"] else "off"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
