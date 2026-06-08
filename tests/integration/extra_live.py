#!/usr/local/bin/python3
# On-box tests: static guard, daemon respawn, persistence across Unbound restart.
import os
import subprocess
import time
import xml.etree.ElementTree as ET

import dns.update
import dns.query
import dns.tsig
import dns.tsigkeyring
import dns.rcode

UCONF = "/var/unbound/unbound.conf"
HE = "/var/unbound/host_entries.conf"
PIDF = "/var/run/keaunbound/kea-unbound-ddns.pid"

g = ET.parse("/conf/config.xml").getroot().find("./OPNsense/KeaUnbound/general")
KNAME = (g.find("tsig_key_name").text or "keaunbound") + "."
KR = dns.tsigkeyring.from_text({KNAME: g.find("tsig_key_secret").text})

P = F = 0


def uc(*a):
    return subprocess.run(["unbound-control", "-c", UCONF] + list(a), capture_output=True, text=True).stdout


def present(s):
    return any(s in ln for ln in uc("list_local_data").splitlines())


def in_file(s):
    try:
        return s in open("/usr/local/etc/unbound.opnsense.d/keaunbound.conf").read()
    except OSError:
        return False


def send(zone, build):
    u = dns.update.Update(zone, keyring=KR, keyname=KNAME, keyalgorithm=dns.tsig.HMAC_SHA256)
    build(u)
    try:
        dns.query.udp(u, "127.0.0.1", port=53535, timeout=5)
    except Exception:
        pass


def check(n, c):
    global P, F
    print(("PASS " if c else "FAIL ") + n)
    P, F = (P + 1, F) if c else (P, F + 1)


# --- A8 static guard: a host_entries.conf entry must never be overwritten ---
orig = open(HE).read() if os.path.exists(HE) else ""
with open(HE, "a") as f:
    f.write('\nlocal-data: "guard-host.internal. 3600 IN A 10.10.10.240"\n')
time.sleep(0.3)
send("internal.", lambda u: u.add("guard-host.internal.", 3600, "A", "10.10.10.99"))
time.sleep(0.5)
check("A8 static guard: DDNS IP not applied", not present("10.10.10.99"))
check("A8 static guard: not added to our file", not in_file("guard-host"))
open(HE, "w").write(orig)  # restore

# --- H daemon(8) respawn after a crash ---
oldpid = int(open(PIDF).read().strip())
os.kill(oldpid, 9)
time.sleep(8)
newpid = int(open(PIDF).read().strip()) if os.path.exists(PIDF) else 0
alive = newpid > 0 and subprocess.run(["ps", "-p", str(newpid)], capture_output=True).returncode == 0
check("H daemon respawn (new live pid)", newpid != oldpid and alive)

# --- J persistence across an Unbound restart (include file) ---
send("internal.", lambda u: u.add("persist-host.internal.", 3600, "A", "10.10.10.241"))
time.sleep(0.6)
before = present("persist-host")
subprocess.run(["configctl", "unbound", "restart"], capture_output=True)
time.sleep(5)
after = present("persist-host")
check("J record present before unbound restart", before)
check("J record still present after unbound restart", after)
send("internal.", lambda u: u.delete("persist-host.internal.", "A", "10.10.10.241"))

print("RESULT pass=%d fail=%d" % (P, F))
