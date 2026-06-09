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


def test_desired_records_dynamic_only(monkeypatch):
    # DYNAMIC ONLY: a dynamic lease gets forward + PTR; a lease on a RESERVED ip
    # is skipped (reservations are OPNsense's), and reservations alone produce
    # nothing (this plugin never registers them).
    monkeypatch.setattr(kea_source, "_reserved_for_family",
                        lambda f: ({"10.0.0.9"}, True) if f == "4" else (set(), True))
    monkeypatch.setattr(kea_source, "leases",
                        lambda f: [("dyn", "10.0.0.5"), ("resv", "10.0.0.9")] if f == "4" else [])
    lines = [r.local_data_line() for r in kea_source.desired_records("home.lan")]
    assert any('dyn.home.lan. 3600 IN A 10.0.0.5' in ln for ln in lines)         # forward
    assert any('5.0.0.10.in-addr.arpa. 3600 IN PTR dyn.home.lan.' in ln for ln in lines)  # reverse
    assert not any('10.0.0.9' in ln for ln in lines)   # reserved-ip lease skipped
    assert not any('resv' in ln for ln in lines)


def test_desired_records_skips_family_with_unreadable_config(monkeypatch):
    # if a family's Kea config is present but unreadable, that whole family is
    # skipped (better no record than misclassifying a reservation as dynamic).
    monkeypatch.setattr(kea_source, "_reserved_for_family",
                        lambda f: (set(), False) if f == "4" else (set(), True))
    monkeypatch.setattr(kea_source, "leases",
                        lambda f: [("v4host", "10.0.0.5")] if f == "4" else [("v6host", "2001:db8::5")])
    lines = [r.local_data_line() for r in kea_source.desired_records("home.lan")]
    assert not any("v4host" in ln or "10.0.0.5" in ln for ln in lines)  # v4 skipped
    assert any("v6host" in ln for ln in lines)                          # v6 still emitted


def test_leases_csv_skips_ia_pd(tmp_path):
    # the v6 memfile holds IA_NA (0) + IA_PD (2); only IA_NA are host addresses.
    future = int(time.time()) + 99999
    c = tmp_path / "l6.csv"
    c.write_text(
        "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,"
        "iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
        f"2001:db8::50,aa,4000,{future},1,4000,0,1,128,1,1,host-na,0,,0\n"
        f"2001:db8:abcd::,aa,4000,{future},1,4000,2,1,56,1,1,deleg-pd,0,,0\n"
    )
    kea_source.CSV6 = str(c)
    addrs = {a for _, a in kea_source.leases_csv("6")}
    assert "2001:db8::50" in addrs            # IA_NA host kept
    assert "2001:db8:abcd::" not in addrs     # IA_PD prefix skipped


def test_lease_source_ok_and_reachable(tmp_path, monkeypatch):
    # socket down + no CSV -> not ok / not reachable
    monkeypatch.setattr(kea_source.kea_ctrl, "send_command", lambda *a, **k: None)
    kea_source.CSV4 = str(tmp_path / "absent4.csv")
    kea_source.CSV6 = str(tmp_path / "absent6.csv")
    assert not kea_source.lease_source_ok("4")
    assert not kea_source.kea_reachable()
    # socket down but a FRESH csv -> ok; a STALE csv -> not ok
    fresh = tmp_path / "fresh.csv"; fresh.write_text("x\n")
    kea_source.CSV4 = str(fresh)
    assert kea_source.lease_source_ok("4")
    old = time.time() - (kea_source.CSV_MAX_AGE + 60)
    import os
    os.utime(str(fresh), (old, old))
    assert not kea_source.lease_source_ok("4")
    # live socket answer -> ok regardless of CSV
    monkeypatch.setattr(kea_source.kea_ctrl, "send_command",
                        lambda *a, **k: {"result": 0})
    assert kea_source.lease_source_ok("6")


def test_desired_records_key_identity(monkeypatch):
    # desired_records produces stable keys for lease-sync/audit. (NOTE: clean's
    # pruning is NOT name-keyed any more — it's IP-keyed in clean.is_stale_record;
    # see test_clean.py. This only covers desired_records' own output.)
    monkeypatch.setattr(kea_source, "_reserved_for_family", lambda f: (set(), True))
    monkeypatch.setattr(kea_source, "leases",
                        lambda f: [("keep", "10.0.0.5")] if f == "4" else [])
    desired = {r.key() for r in kea_source.desired_records("home.lan")}
    assert ("keep.home.lan.", "A", "10.0.0.5") in desired
    assert ("5.0.0.10.in-addr.arpa.", "PTR", "keep.home.lan.") in desired


def test_reserved_for_family_error_translation(tmp_path):
    # unparseable config -> (empty, NOT readable); missing -> (empty, readable);
    # valid-but-empty -> (set, readable)
    bad = tmp_path / "bad4.conf"
    bad.write_text("{ not json")
    kea_source.KEA4 = str(bad)
    assert kea_source._reserved_for_family("4") == (set(), False)
    kea_source.KEA4 = str(tmp_path / "absent4.conf")
    assert kea_source._reserved_for_family("4") == (set(), True)
    ok = tmp_path / "ok4.conf"
    ok.write_text(json.dumps({"Dhcp4": {"reservations": [
        {"hostname": "h", "ip-address": "10.0.0.5"}]}}))
    kea_source.KEA4 = str(ok)
    assert kea_source._reserved_for_family("4") == ({"10.0.0.5"}, True)


def test_leases_socket_skips_ia_pd(monkeypatch):
    # the control-socket path must keep only IA_NA (host addresses), never IA_PD.
    resp = {"result": 0, "arguments": {"leases": [
        {"hostname": "host-na", "ip-address": "2001:db8::50", "state": 0, "type": "IA_NA"},
        {"hostname": "deleg-pd", "ip-address": "2001:db8:abcd::", "state": 0, "type": "IA_PD"},
    ]}}
    monkeypatch.setattr(kea_source.kea_ctrl, "send_command", lambda *a, **k: resp)
    out = dict(kea_source.leases("6"))
    assert out.get("host-na") == "2001:db8::50"
    assert "deleg-pd" not in out


def test_clean_inputs_single_fetch(monkeypatch):
    # live IPs exclude reservations; both families confirmed from one fetch each.
    monkeypatch.setattr(kea_source, "_reserved_for_family",
                        lambda f: ({"10.0.0.9"}, True) if f == "4" else (set(), True))
    monkeypatch.setattr(kea_source, "_family_leases",
                        lambda f: ([("dyn", "10.0.0.5"), ("resv", "10.0.0.9")], True)
                        if f == "4" else ([("v6", "2001:db8::5")], True))
    live, prunable = kea_source.clean_inputs()
    assert live["4"] == {"10.0.0.5"}          # reserved 10.0.0.9 excluded
    assert live["6"] == {"2001:db8::5"}
    assert prunable == {"4": True, "6": True}


def test_clean_inputs_unconfirmed_source_not_prunable(monkeypatch):
    # socket down + stale/absent CSV -> source_ok False -> family not prunable
    monkeypatch.setattr(kea_source, "_reserved_for_family", lambda f: (set(), True))
    monkeypatch.setattr(kea_source, "_family_leases", lambda f: ([], False))
    live, prunable = kea_source.clean_inputs()
    assert prunable == {"4": False, "6": False}


def test_clean_inputs_unreadable_reserved_not_prunable(monkeypatch):
    # reserved config present-but-unreadable -> not prunable, no live IPs collected
    monkeypatch.setattr(kea_source, "_reserved_for_family", lambda f: (set(), False))
    monkeypatch.setattr(kea_source, "_family_leases", lambda f: ([("h", "10.0.0.5")], True))
    live, prunable = kea_source.clean_inputs()
    assert prunable == {"4": False, "6": False}
    assert live["4"] == set() and live["6"] == set()


def test_family_leases_socket_vs_fresh_csv(monkeypatch, tmp_path):
    # socket result==0 -> authoritative; socket down + stale CSV -> ([], False)
    monkeypatch.setattr(kea_source.kea_ctrl, "send_command",
                        lambda *a, **k: {"result": 0, "arguments": {"leases": [
                            {"hostname": "h", "ip-address": "10.0.0.5", "state": 0}]}})
    out, ok = kea_source._family_leases("4")
    assert ok is True and ("h", "10.0.0.5") in out
    monkeypatch.setattr(kea_source.kea_ctrl, "send_command", lambda *a, **k: None)
    kea_source.CSV4 = str(tmp_path / "absent.csv")
    assert kea_source._family_leases("4") == ([], False)


def test_family_leases_fresh_csv_fallback(monkeypatch, tmp_path):
    # socket down + a FRESH CSV -> trust it (the production fallback path)
    monkeypatch.setattr(kea_source.kea_ctrl, "send_command", lambda *a, **k: None)
    c = tmp_path / "l4.csv"
    c.write_text(
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,"
        "fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
        f"10.0.0.7,aa,bb,4000,{int(time.time())+99999},1,1,1,csvhost,0,,0\n")
    kea_source.CSV4 = str(c)  # just written -> fresh
    out, ok = kea_source._family_leases("4")
    assert ok is True
    assert ("csvhost", "10.0.0.7") in out


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
