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


def test_patch_dhcp_per_subnet_suffix(tmp_path):
    # issue #17: a subnet with its own domain-name option gets a per-subnet
    # ddns-qualifying-suffix; one matching the global, or with no domain, inherits.
    m = load_injector(tmp_path)
    p = tmp_path / "k4.json"
    json.dump({"Dhcp4": {"subnet4": [
        {"subnet": "10.0.0.0/24",                                  # own domain -> override
         "option-data": [{"name": "domain-name", "data": "iot.lan"}]},
        {"subnet": "10.1.0.0/24",                                  # == global -> inherit
         "option-data": [{"name": "domain-name", "data": "home.lan"}]},
        {"subnet": "10.2.0.0/24"},                                 # no domain -> inherit
    ]}}, open(p, "w"))
    assert m.patch_dhcp(str(p), "Dhcp4", SETTINGS) is True         # SETTINGS suffix=home.lan
    subs = json.load(open(p))["Dhcp4"]["subnet4"]
    assert subs[0]["ddns-qualifying-suffix"] == "iot.lan"          # differs -> set
    assert "ddns-qualifying-suffix" not in subs[1]                 # equals global -> inherit
    assert "ddns-qualifying-suffix" not in subs[2]                 # no domain -> inherit
    assert m.patch_dhcp(str(p), "Dhcp4", SETTINGS) is False        # idempotent


def test_patch_dhcp_per_subnet_suffix_in_shared_network(tmp_path):
    # shared-network subnets are covered too.
    m = load_injector(tmp_path)
    p = tmp_path / "k4.json"
    json.dump({"Dhcp4": {"subnet4": [], "shared-networks": [{"name": "sn", "subnet4": [
        {"subnet": "10.5.0.0/24",
         "option-data": [{"name": "domain-name", "data": "guest.lan"}]}]}]}}, open(p, "w"))
    assert m.patch_dhcp(str(p), "Dhcp4", SETTINGS) is True
    sn = json.load(open(p))["Dhcp4"]["shared-networks"][0]["subnet4"][0]
    assert sn["ddns-qualifying-suffix"] == "guest.lan"


def test_patch_d2_multi_suffix(tmp_path):
    # issue #17: one forward zone per distinct suffix in s["suffixes"], all pointed
    # at our listener with our key; "." kept as the harmless fallback.
    m = load_injector(tmp_path)
    p = tmp_path / "d2.json"
    json.dump({"DhcpDdns": {"forward-ddns": {"ddns-domains": []},
                            "reverse-ddns": {"ddns-domains": []}, "tsig-keys": []}}, open(p, "w"))
    s = dict(SETTINGS, suffixes=["home.lan", "iot.lan", "guest.lan"])
    assert m.patch_d2(str(p), s) is True
    fwd = {x["name"]: x for x in json.load(open(p))["DhcpDdns"]["forward-ddns"]["ddns-domains"]}
    for z in ("home.lan.", "iot.lan.", "guest.lan.", "."):
        assert z in fwd
        assert fwd[z]["dns-servers"][0] == {"ip-address": "127.0.0.1", "port": 53535}
        assert fwd[z]["key-name"] == "keaunbound."
    assert m.patch_d2(str(p), s) is False                          # idempotent


def test_collect_suffixes(tmp_path):
    # global first, then per-subnet domains across both families, deduped (ci).
    m = load_injector(tmp_path)
    m.KEA4 = str(tmp_path / "k4.json")
    m.KEA6 = str(tmp_path / "k6.json")
    json.dump({"Dhcp4": {"subnet4": [
        {"option-data": [{"name": "domain-name", "data": "iot.lan"}]},
        {"option-data": [{"name": "domain-name", "data": "Home.LAN"}]},   # dup of global (ci)
    ]}}, open(m.KEA4, "w"))
    json.dump({"Dhcp6": {"subnet6": [
        {"option-data": [{"name": "domain-name", "data": "v6.lan"}]}]}}, open(m.KEA6, "w"))
    out = m._collect_suffixes("home.lan")
    assert out[0] == "home.lan"                       # global first
    assert "iot.lan" in out and "v6.lan" in out
    assert sum(1 for x in out if x.lower() == "home.lan") == 1   # deduped case-insensitively


def test_patch_dhcp_merges_existing_ddns_block(tmp_path):
    # a user's extra dhcp-ddns keys must be preserved, only the connection params
    # we require are forced (non-destructive merge, not a clobber).
    m = load_injector(tmp_path)
    p = tmp_path / "k4.json"
    json.dump({"Dhcp4": {"subnet4": [], "dhcp-ddns": {
        "enable-updates": False, "max-queue-size": 2048, "sender-ip": "127.0.0.2",
    }}}, open(p, "w"))
    assert m.patch_dhcp(str(p), "Dhcp4", SETTINGS) is True
    block = json.load(open(p))["Dhcp4"]["dhcp-ddns"]
    assert block["enable-updates"] is True            # forced on
    assert block["server-ip"] == "127.0.0.1"          # forced to our D2
    assert block["max-queue-size"] == 2048            # user key preserved
    assert block["sender-ip"] == "127.0.0.2"          # user key preserved


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
