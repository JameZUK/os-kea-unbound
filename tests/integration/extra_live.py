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

# --- A14 reserved-record protection: a reserved host's record placed by OPNsense
#     (runtime, as host_entries would) must SURVIVE a DDNS delete — the listener
#     must never evict it. (Test Kea reserves reserved-host -> 10.10.10.50.) ---
RIP, RPTR = "10.10.10.50", "50.10.10.10.in-addr.arpa."
uc("local_data", "reserved-host.internal. 3600 IN A " + RIP)            # OPNsense's record
uc("local_data", "%s 3600 IN PTR reserved-host.internal." % RPTR)
time.sleep(0.3)
check("A14 reserved A+PTR present", present(RIP) and present(RPTR))
send("internal.", lambda u: u.delete("reserved-host.internal.", "A", RIP))      # specific
time.sleep(0.3)
send("10.10.10.in-addr.arpa.", lambda u: u.delete(RPTR))                         # ANY (reverse)
time.sleep(0.5)
check("A14 reserved A survives delete", present(RIP))
check("A14 reserved PTR survives delete", present(RPTR))
uc("local_data_remove", "reserved-host.internal.")
uc("local_data_remove", RPTR)
# a non-reserved record is still removable by a DDNS delete
send("internal.", lambda u: u.add("ephemeral.internal.", 3600, "A", "10.10.10.72"))
time.sleep(0.3)
send("internal.", lambda u: u.delete("ephemeral.internal.", "A", "10.10.10.72"))
time.sleep(0.4)
check("A14 non-reserved A still removable", not present("10.10.10.72"))
uc("local_data_remove", "reserved-host.internal.")   # clean up test artifacts
uc("local_data_remove", RPTR)

# --- A15 lease lifecycle: an add-NCR registers, a delete-NCR (lease release)
#     removes — the native-DDNS equivalent of the old lease*_committed /
#     lease*_expire hook tests. ---
send("internal.", lambda u: u.add("leaselife.internal.", 1800, "A", "10.10.10.81"))
time.sleep(0.3)
send("10.10.10.in-addr.arpa.",
     lambda u: u.add("81.10.10.10.in-addr.arpa.", 1800, "PTR", "leaselife.internal."))
time.sleep(0.4)
check("A15 lease add: A+PTR present",
      present("10.10.10.81") and present("81.10.10.10.in-addr.arpa."))
send("internal.", lambda u: u.delete("leaselife.internal.", "A", "10.10.10.81"))
time.sleep(0.3)
send("10.10.10.in-addr.arpa.", lambda u: u.delete("81.10.10.10.in-addr.arpa."))
time.sleep(0.4)
check("A15 lease release: A removed", not present("10.10.10.81"))
check("A15 lease release: PTR removed", not present("81.10.10.10.in-addr.arpa."))

# --- A16 multiple RRsets in one UPDATE packet are all applied (old multi-lease
#     leases*_committed). handle() iterates every RRset in msg.authority. ---
def _multi(u):
    u.add("multi1.internal.", 1800, "A", "10.10.10.82")
    u.add("multi2.internal.", 1800, "A", "10.10.10.83")
    u.add("multi1.internal.", 1800, "AAAA", "2001:db8::82")
send("internal.", _multi)
time.sleep(0.6)
check("A16 multi-RRset: host1 A", present("10.10.10.82"))
check("A16 multi-RRset: host2 A", present("10.10.10.83"))
check("A16 multi-RRset: host1 AAAA", present("2001:db8::82"))
for n in ("multi1.internal.", "multi2.internal."):
    uc("local_data_remove", n)

# --- A17 dual-stack added v6 THEN v4 (old TEST 4 ordering): both resolve, and a
#     v6 removal leaves the v4 A intact. ---
send("internal.", lambda u: u.add("v6first.internal.", 1800, "AAAA", "2001:db8::84"))
time.sleep(0.3)
send("internal.", lambda u: u.add("v6first.internal.", 1800, "A", "10.10.10.84"))
time.sleep(0.4)
check("A17 v6->v4 order: both present",
      present("2001:db8::84") and present("10.10.10.84"))
send("internal.", lambda u: u.delete("v6first.internal.", "AAAA", "2001:db8::84"))
time.sleep(0.4)
check("A17 v6->v4 order: AAAA removed, A preserved",
      present("10.10.10.84") and not present("2001:db8::84"))
uc("local_data_remove", "v6first.internal.")

# --- A18 dynamic-only: a DDNS add for a RESERVED host is skipped (its DNS is
#     OPNsense's); a dynamic (non-reserved) host is registered. Test Kea
#     reserves reserved-host -> 10.10.10.50. ---
send("internal.", lambda u: u.add("reserved-host.internal.", 1800, "A", "10.10.10.50"))
time.sleep(0.4)
check("A18 reserved host NOT registered by plugin", not in_file("reserved-host"))
send("internal.", lambda u: u.add("dynhost.internal.", 1800, "A", "10.10.10.66"))
time.sleep(0.4)
check("A18 dynamic host IS registered (fwd)", present("10.10.10.66") and in_file("dynhost"))
uc("local_data_remove", "dynhost.internal.")

# --- A19 TSIG algorithm pinning: a MAC valid under a DIFFERENT algorithm than the
#     one configured (hmac-sha256) must be rejected — not just any valid MAC for
#     the key. Sign the same key with hmac-sha1 and confirm it's dropped. ---
def send_algo(zone, build, algo):
    u = dns.update.Update(zone, keyring=KR, keyname=KNAME, keyalgorithm=algo)
    build(u)
    try:
        dns.query.udp(u, "127.0.0.1", port=53535, timeout=5)
    except Exception:
        pass


send_algo("internal.", lambda u: u.add("algotest.internal.", 1800, "A", "10.10.10.79"),
          dns.tsig.HMAC_SHA1)
time.sleep(0.4)
check("A19 wrong-algorithm UPDATE rejected", not present("10.10.10.79"))
send("internal.", lambda u: u.add("algook.internal.", 1800, "A", "10.10.10.78"))
time.sleep(0.4)
check("A19 correct-algorithm UPDATE still applied", present("10.10.10.78"))
uc("local_data_remove", "algook.internal.")

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
