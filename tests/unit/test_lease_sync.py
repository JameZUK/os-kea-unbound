import importlib.util
import json
import pathlib
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
LS = ROOT / "src/opnsense/scripts/keaunbound/lease-sync.py"


def load(tmp_path):
    spec = importlib.util.spec_from_file_location("lease_sync", LS)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.LOG = str(tmp_path / "keaunbound.log")
    return m


def test_reservations_v4_global_and_subnet(tmp_path):
    m = load(tmp_path)
    p = tmp_path / "k4.json"
    json.dump({"Dhcp4": {
        "reservations": [{"hostname": "glob", "ip-address": "10.0.0.5"}],
        "subnet4": [{"subnet": "10.0.0.0/24", "reservations": [
            {"hostname": "res1", "ip-address": "10.0.0.10"},
            {"hostname": "", "ip-address": "10.0.0.11"},          # nameless -> skipped
        ]}],
    }}, open(p, "w"))
    res = m.reservations(str(p), "4")
    assert ("glob", "10.0.0.5") in res
    assert ("res1", "10.0.0.10") in res
    assert all(h for h, _ in res)            # no nameless entries


def test_reservations_v6_addresses_list(tmp_path):
    m = load(tmp_path)
    p = tmp_path / "k6.json"
    json.dump({"Dhcp6": {"subnet6": [{"subnet": "fd00::/64", "reservations": [
        {"hostname": "v6h", "ip-addresses": ["fd00::5"]}]}]}}, open(p, "w"))
    assert ("v6h", "fd00::5") in m.reservations(str(p), "6")


def test_leases_csv_filters_expired_and_nonzero_state(tmp_path):
    m = load(tmp_path)
    future = int(time.time()) + 99999
    csvp = tmp_path / "l4.csv"
    csvp.write_text(
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,"
        "fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
        f"10.0.0.50,aa,bb,4000,{future},1,1,1,host50,0,,0\n"
        f"10.0.0.51,aa,bb,4000,1,1,1,1,expired51,0,,0\n"          # expired
        f"10.0.0.52,aa,bb,4000,{future},1,1,1,declined52,1,,0\n"  # state != 0
    )
    m.CSV4 = str(csvp)
    addrs = {a for _, a in m.leases_csv("4")}
    assert "10.0.0.50" in addrs
    assert "10.0.0.51" not in addrs
    assert "10.0.0.52" not in addrs


def test_leases_csv_newest_row_wins(tmp_path):
    m = load(tmp_path)
    future = int(time.time()) + 99999
    csvp = tmp_path / "l4.csv"
    csvp.write_text(
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,"
        "fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
        f"10.0.0.60,aa,bb,4000,{future},1,1,1,oldname,0,,0\n"
        f"10.0.0.60,aa,bb,4000,{future},1,1,1,newname,0,,0\n"     # append-only: newest wins
    )
    m.CSV4 = str(csvp)
    res = dict((a, h) for h, a in m.leases_csv("4"))
    assert res["10.0.0.60"] == "newname"


def test_disabled_no_settings(tmp_path):
    m = load(tmp_path)
    cfg = tmp_path / "config.xml"
    cfg.write_text("<opnsense><system><domain>x</domain></system></opnsense>")
    m.CONFIG = str(cfg)
    assert m.load_settings() is None
