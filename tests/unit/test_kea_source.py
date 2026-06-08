import json
import time

from lib import kea_source
from lib import records as R


def test_reservations_v4_global_and_subnet(tmp_path):
    p = tmp_path / "k4.json"
    p.write_text(json.dumps({"Dhcp4": {
        "reservations": [{"hostname": "glob", "ip-address": "10.0.0.5"}],
        "subnet4": [{"subnet": "10.0.0.0/24", "reservations": [
            {"hostname": "res1", "ip-address": "10.0.0.10"},
            {"hostname": "", "ip-address": "10.0.0.11"},
        ]}],
    }}))
    res = kea_source.reservations(str(p), "4")
    assert ("glob", "10.0.0.5") in res and ("res1", "10.0.0.10") in res
    assert all(h for h, _ in res)


def test_reservations_v6_addresses_list(tmp_path):
    p = tmp_path / "k6.json"
    p.write_text(json.dumps({"Dhcp6": {"subnet6": [{"subnet": "fd00::/64", "reservations": [
        {"hostname": "v6h", "ip-addresses": ["fd00::5"]}]}]}}))
    assert ("v6h", "fd00::5") in kea_source.reservations(str(p), "6")


def test_leases_csv_filters_expired_and_state(tmp_path):
    future = int(time.time()) + 99999
    c = tmp_path / "l4.csv"
    c.write_text(
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,"
        "fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
        f"10.0.0.50,aa,bb,4000,{future},1,1,1,host50,0,,0\n"
        f"10.0.0.51,aa,bb,4000,1,1,1,1,expired51,0,,0\n"
        f"10.0.0.52,aa,bb,4000,{future},1,1,1,declined52,1,,0\n"
    )
    kea_source.CSV4 = str(c)
    addrs = {a for _, a in kea_source.leases_csv("4")}
    assert "10.0.0.50" in addrs
    assert "10.0.0.51" not in addrs and "10.0.0.52" not in addrs


def test_desired_records(tmp_path, monkeypatch):
    monkeypatch.setattr(kea_source, "reservations",
                        lambda p, f: [("host", "10.0.0.5")] if f == "4" else [])
    monkeypatch.setattr(kea_source, "leases", lambda f: [])
    lines = [r.local_data_line() for r in kea_source.desired_records("home.lan")]
    assert any('host.home.lan. 3600 IN A 10.0.0.5' in ln for ln in lines)
    assert any('IN PTR host.home.lan.' in ln for ln in lines)


def test_stale_detection_set_diff(monkeypatch):
    monkeypatch.setattr(kea_source, "reservations",
                        lambda p, f: [("keep", "10.0.0.5")] if f == "4" else [])
    monkeypatch.setattr(kea_source, "leases", lambda f: [])
    desired = {r.key() for r in kea_source.desired_records("home.lan")}
    actual = R.parse_local_data_lines(
        'local-data: "keep.home.lan. 3600 IN A 10.0.0.5"\n'
        'local-data: "gone.home.lan. 3600 IN A 10.0.0.9"\n'
    )
    stale = [r for r in actual if r.key() not in desired]
    assert len(stale) == 1 and stale[0].rdata == "10.0.0.9"


def test_load_settings(tmp_path):
    off = tmp_path / "off.xml"
    off.write_text("<opnsense><system><domain>x</domain></system></opnsense>")
    assert kea_source.load_settings(str(off)) is None

    on = tmp_path / "on.xml"
    on.write_text(
        "<opnsense><system><domain>box.lan</domain></system>"
        "<OPNsense><KeaUnbound><general><enabled>1</enabled>"
        "<qualifying_suffix></qualifying_suffix></general></KeaUnbound></OPNsense></opnsense>"
    )
    s = kea_source.load_settings(str(on))
    assert s and s["suffix"] == "box.lan"
