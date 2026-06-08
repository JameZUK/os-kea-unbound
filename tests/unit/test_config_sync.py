import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
INJECTOR = ROOT / "src/opnsense/scripts/keaunbound/kea-config-sync.py"

SETTINGS = {
    "port": 53535, "suffix": "home.lan", "tsig": True,
    "tsig_name": "keaunbound", "tsig_secret": "YWJjZA==", "tsig_algo": "HMAC-SHA256",
}


def load_injector(tmp_path):
    spec = importlib.util.spec_from_file_location("kcs", INJECTOR)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.LOG = str(tmp_path / "keaunbound.log")  # don't write to /var/log in tests
    return m


def test_patch_dhcp_global_and_subnet_override(tmp_path):
    m = load_injector(tmp_path)
    p = tmp_path / "k4.json"
    json.dump({"Dhcp4": {"subnet4": [
        {"subnet": "10.0.0.0/24", "ddns-send-updates": False},   # Kea default -> strip
        {"subnet": "10.1.0.0/24", "ddns-send-updates": True},    # explicit user -> keep
    ]}}, open(p, "w"))
    assert m.patch_dhcp(str(p), "Dhcp4", SETTINGS) is True
    c = json.load(open(p))["Dhcp4"]
    assert c["ddns-send-updates"] is True
    assert c["ddns-qualifying-suffix"] == "home.lan"
    assert c["ddns-replace-client-name"] == "when-not-present"
    subs = c["subnet4"]
    assert "ddns-send-updates" not in subs[0]      # false stripped -> inherits global true
    assert subs[1]["ddns-send-updates"] is True     # explicit true preserved
    # master switch (dhcp-ddns.enable-updates) must be set, pointed at D2's default
    assert c["dhcp-ddns"]["enable-updates"] is True
    assert c["dhcp-ddns"]["server-ip"] == "127.0.0.1"
    assert c["dhcp-ddns"]["server-port"] == 53001
    assert c["ddns-update-on-renew"] is True        # defaults on
    assert m.patch_dhcp(str(p), "Dhcp4", SETTINGS) is False  # idempotent


def test_patch_dhcp_update_on_renew_off(tmp_path):
    m = load_injector(tmp_path)
    p = tmp_path / "k4.json"
    json.dump({"Dhcp4": {"subnet4": []}}, open(p, "w"))
    settings = dict(SETTINGS, update_on_renew=False)
    assert m.patch_dhcp(str(p), "Dhcp4", settings) is True
    c = json.load(open(p))["Dhcp4"]
    assert c["ddns-update-on-renew"] is False
    assert c["dhcp-ddns"]["enable-updates"] is True   # master switch unaffected


def test_patch_d2_preserves_user_config(tmp_path):
    m = load_injector(tmp_path)
    p = tmp_path / "d2.json"
    json.dump({"DhcpDdns": {
        "forward-ddns": {"ddns-domains": [
            {"name": "corp.example.com.", "dns-servers": [{"ip-address": "10.0.0.53"}], "key-name": "corpkey."}]},
        "reverse-ddns": {"ddns-domains": []},
        "tsig-keys": [{"name": "corpkey.", "algorithm": "HMAC-SHA256", "secret": "Y29ycA=="}],
    }}, open(p, "w"))
    assert m.patch_d2(str(p), SETTINGS) is True
    d = json.load(open(p))["DhcpDdns"]
    fwd = [x["name"] for x in d["forward-ddns"]["ddns-domains"]]
    assert "corp.example.com." in fwd and "." in fwd          # user preserved + catch-all added
    assert [x["name"] for x in d["reverse-ddns"]["ddns-domains"]] == ["in-addr.arpa.", "ip6.arpa."]
    keys = [x["name"] for x in d["tsig-keys"]]
    assert "corpkey." in keys and "keaunbound." in keys        # user key preserved + ours added
    catchall = next(x for x in d["forward-ddns"]["ddns-domains"] if x["name"] == ".")
    assert catchall["dns-servers"][0] == {"ip-address": "127.0.0.1", "port": 53535}
    assert catchall["key-name"] == "keaunbound."
    assert m.patch_d2(str(p), SETTINGS) is False               # idempotent


def test_disabled_plugin_yields_no_settings(tmp_path):
    m = load_injector(tmp_path)
    cfg = tmp_path / "config.xml"
    cfg.write_text("<opnsense><system><domain>x</domain></system></opnsense>")
    m.CONFIG = str(cfg)
    assert m.load_settings() is None


def test_qualifying_suffix_defaults_to_domain(tmp_path):
    m = load_injector(tmp_path)
    cfg = tmp_path / "config.xml"
    cfg.write_text(
        "<opnsense><system><domain>box.lan</domain></system>"
        "<OPNsense><KeaUnbound><general>"
        "<enabled>1</enabled><qualifying_suffix></qualifying_suffix>"
        "<tsig_enabled>1</tsig_enabled><tsig_key_secret>YWJjZA==</tsig_key_secret>"
        "</general></KeaUnbound></OPNsense></opnsense>"
    )
    m.CONFIG = str(cfg)
    s = m.load_settings()
    assert s is not None and s["suffix"] == "box.lan"
