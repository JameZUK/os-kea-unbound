#!/usr/local/bin/python3
# On-box integration test for the DDNS listener. Sends real (TSIG-signed) RFC2136
# UPDATEs and checks the effect in Unbound. Run on the OPNsense test host.
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import dns.update
import dns.query
import dns.tsig
import dns.tsigkeyring
import dns.rcode

UCONF = "/var/unbound/unbound.conf"
HOST, PORT = "127.0.0.1", 53535

g = ET.parse("/conf/config.xml").getroot().find("./OPNsense/KeaUnbound/general")
SECRET = g.find("tsig_key_secret").text
KNAME = (g.find("tsig_key_name").text or "keaunbound") + "."
KR = dns.tsigkeyring.from_text({KNAME: SECRET})
WRONG = dns.tsigkeyring.from_text({KNAME: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="})

P = F = 0


def uc(*a):
    return subprocess.run(["unbound-control", "-c", UCONF] + list(a),
                          capture_output=True, text=True).stdout


def present(substr):
    return any(substr in ln for ln in uc("list_local_data").splitlines())


def send(zone, build, keyring=KR):
    if keyring is not None:
        u = dns.update.Update(zone, keyring=keyring, keyname=KNAME,
                              keyalgorithm=dns.tsig.HMAC_SHA256)
    else:
        u = dns.update.Update(zone)
    build(u)
    try:
        r = dns.query.udp(u, HOST, port=PORT, timeout=5)
        return dns.rcode.to_text(r.rcode())
    except Exception as e:
        return "ERR:%s" % e


def check(name, cond):
    global P, F
    print(("PASS " if cond else "FAIL ") + name)
    P, F = (P + 1, F) if cond else (P, F + 1)


def cleanup():
    for n in ("ta.internal.", "tb.internal.", "tc.internal."):
        send("internal.", lambda u, n=n: u.delete(n))
    time.sleep(0.3)


cleanup()

# A1 forward A
send("internal.", lambda u: u.add("ta.internal.", 3600, "A", "10.10.10.211")); time.sleep(0.3)
check("A1 add A", present("ta.internal.") and present("10.10.10.211"))

# A3 reverse PTR
send("10.10.10.in-addr.arpa.", lambda u: u.add("211.10.10.10.in-addr.arpa.", 3600, "PTR", "ta.internal.")); time.sleep(0.3)
check("A3 add PTR", present("211.10.10.10.in-addr.arpa."))

# A2 add AAAA to same host (dual-stack)
send("internal.", lambda u: u.add("ta.internal.", 3600, "AAAA", "2001:db8::a11")); time.sleep(0.3)
check("A2 add AAAA", present("2001:db8::a11"))

# A4 delete A only -> AAAA preserved
send("internal.", lambda u: u.delete("ta.internal.", "A", "10.10.10.211")); time.sleep(0.3)
check("A4 dual-stack: A removed", not present("10.10.10.211"))
check("A4 dual-stack: AAAA preserved", present("2001:db8::a11"))

# A5 delete AAAA -> host gone
send("internal.", lambda u: u.delete("ta.internal.", "AAAA", "2001:db8::a11")); time.sleep(0.3)
check("A5 delete AAAA", not present("2001:db8::a11"))

# A6 aggressive cleanup: same host moves IP -> old A removed
send("internal.", lambda u: u.add("tb.internal.", 3600, "A", "10.10.10.212")); time.sleep(0.3)
send("internal.", lambda u: u.add("tb.internal.", 3600, "A", "10.10.10.213")); time.sleep(0.3)
check("A6 aggressive: old IP removed", not present("10.10.10.212"))
check("A6 aggressive: new IP present", present("10.10.10.213"))

# A7 TSIG security
send("internal.", lambda u: u.add("tc.internal.", 3600, "A", "10.10.10.221"), keyring=None); time.sleep(0.3)
check("A7a unsigned UPDATE rejected", not present("10.10.10.221"))
send("internal.", lambda u: u.add("tc.internal.", 3600, "A", "10.10.10.222"), keyring=WRONG); time.sleep(0.3)
check("A7b wrong-key UPDATE rejected", not present("10.10.10.222"))

send("internal.", lambda u: u.delete("tb.internal."))
cleanup()
print("RESULT pass=%d fail=%d" % (P, F))
sys.exit(1 if F else 0)
