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

# --- A10/A11 static PTR must survive a DDNS ANY-delete, both v4 and v6.
#     Regression: a lease release sends "delete all RRsets at <reverse name>";
#     local_data_remove drops the WHOLE name, which wiped the reserved host's
#     static PTR loaded from host_entries.conf. Also: DHCID must not be written. ---
import ipaddress  # noqa: E402
for tag, ip, fqdn in [
    ("A10 v4", "10.10.10.242", "static-rev4.internal."),
    ("A11 v6", "2001:db8::242", "static-rev6.internal."),
]:
    ptr = ipaddress.ip_address(ip).reverse_pointer + "."
    orig_he = open(HE).read() if os.path.exists(HE) else ""
    with open(HE, "a") as f:
        f.write('\nlocal-data-ptr: "%s %s"\n' % (ip, fqdn.rstrip(".")))
    uc("local_data", "%s 3600 IN PTR %s" % (ptr, fqdn))   # as an unbound (re)load would
    time.sleep(0.3)
    # DDNS for the reserved host: ADD PTR (+DHCID), then a lease-release ANY-delete.
    send(ptr, lambda u, p=ptr, fq=fqdn: u.add(p, 1333, "PTR", fq))
    try:
        send(ptr, lambda u, p=ptr: u.add(p, 1333, "DHCID", "AAABBBCCCDDDEEE="))
    except Exception:
        pass
    time.sleep(0.3)
    send(ptr, lambda u, p=ptr: u.delete(p))   # ANY-delete the whole name
    time.sleep(0.5)
    check(tag + " static PTR survives ANY-delete", present(fqdn))
    check(tag + " DHCID not written", not present("DHCID"))
    uc("local_data_remove", ptr)
    open(HE, "w").write(orig_he)

# --- A12 dual-stack forward: a name-wide (ANY) delete must NOT drop the other
#     family. kea-dhcp4 and kea-dhcp6 write the same FQDN independently, so a v6
#     removal's name-wide cleanup must not wipe the v4 A (and vice versa). ---
send("internal.", lambda u: u.add("dual.internal.", 3600, "A", "10.10.10.61"))
time.sleep(0.3)
send("internal.", lambda u: u.add("dual.internal.", 3600, "AAAA", "2001:db8::61"))
time.sleep(0.4)
check("A12 dual-stack both present before ANY-delete",
      present("10.10.10.61") and present("2001:db8::61"))
send("internal.", lambda u: u.delete("dual.internal."))   # name-wide ANY delete
time.sleep(0.5)
check("A12 forward ANY-delete keeps A", present("10.10.10.61"))
check("A12 forward ANY-delete keeps AAAA", present("2001:db8::61"))
# specific deletes still work (and clean up)
send("internal.", lambda u: u.delete("dual.internal.", "A", "10.10.10.61"))
time.sleep(0.3)
check("A12 specific A delete keeps AAAA", present("2001:db8::61") and not present("10.10.10.61"))
send("internal.", lambda u: u.delete("dual.internal.", "AAAA", "2001:db8::61"))

# --- A13 a non-static REVERSE PTR must still be removable by an ANY-delete ---
send("10.10.10.in-addr.arpa.", lambda u: u.add("62.10.10.10.in-addr.arpa.", 3600, "PTR", "revtest.internal."))
time.sleep(0.4)
check("A13 reverse PTR present before ANY-delete", present("62.10.10.10.in-addr.arpa."))
send("10.10.10.in-addr.arpa.", lambda u: u.delete("62.10.10.10.in-addr.arpa."))   # ANY delete
time.sleep(0.5)
check("A13 reverse ANY-delete removes PTR", not present("62.10.10.10.in-addr.arpa."))

# --- A14 reservation-aware guard: a reserved IP's records survive a DDNS delete
#     even when NOT in host_entries.conf — closes the host_entries regeneration
#     race. (Test Kea reserves reserved-host -> 10.10.10.50.) ---
RIP, RPTR = "10.10.10.50", "50.10.10.10.in-addr.arpa."
send("internal.", lambda u: u.add("reserved-host.internal.", 3600, "A", RIP))
time.sleep(0.3)
send("10.10.10.in-addr.arpa.", lambda u: u.add(RPTR, 3600, "PTR", "reserved-host.internal."))
time.sleep(0.4)
check("A14 reserved A+PTR present", present(RIP) and present(RPTR))
send("internal.", lambda u: u.delete("reserved-host.internal.", "A", RIP))      # specific
time.sleep(0.3)
send("10.10.10.in-addr.arpa.", lambda u: u.delete(RPTR))                         # ANY (reverse)
time.sleep(0.5)
check("A14 reserved A survives delete", present(RIP))
check("A14 reserved PTR survives delete", present(RPTR))
send("internal.", lambda u: u.add("ephemeral.internal.", 3600, "A", "10.10.10.72"))
time.sleep(0.3)
send("internal.", lambda u: u.delete("ephemeral.internal.", "A", "10.10.10.72"))
time.sleep(0.4)
check("A14 non-reserved A still removable", not present("10.10.10.72"))
uc("local_data_remove", "reserved-host.internal.")   # clean up test artifacts
uc("local_data_remove", RPTR)

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
