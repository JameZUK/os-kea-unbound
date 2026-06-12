from lib import suffix as S


def test_norm_and_clean():
    assert S.norm("  Home.LAN.  ") == "home.lan"
    assert S.norm("") == "" and S.norm(None) == ""
    assert S.clean("  iot.lan.  ") == "iot.lan"   # trims + drops trailing dot, keeps case
    assert S.clean("IoT.LAN") == "IoT.LAN"


def test_domain_name_option():
    sn = {"option-data": [{"name": "routers", "data": "10.0.0.1"},
                          {"name": "domain-name", "data": "iot.lan"}]}
    assert S.domain_name_option(sn) == "iot.lan"
    assert S.domain_name_option({"option-data": []}) == ""
    assert S.domain_name_option({}) == ""
    # blank domain-name is treated as unset
    assert S.domain_name_option({"option-data": [{"name": "domain-name", "data": "  "}]}) == ""


def test_subnet_suffix_precedence():
    own = {"option-data": [{"name": "domain-name", "data": "iot.lan"}]}
    assert S.subnet_suffix(own, "home.lan") == "iot.lan"          # option wins
    assert S.subnet_suffix({}, "home.lan") == "home.lan"          # fallback to global
    assert S.subnet_suffix({}, "") == ""                          # neither


def test_iter_subnets_includes_shared_networks():
    root = {"subnet4": [{"id": 1}],
            "shared-networks": [{"subnet4": [{"id": 2}, {"id": 3}]}]}
    ids = [sn.get("id") for sn in S.iter_subnets(root, "subnet4")]
    assert ids == [1, 2, 3]


def test_suffix_by_subnet_id():
    root = {"subnet4": [
        {"id": 1, "option-data": [{"name": "domain-name", "data": "iot.lan"}]},
        {"id": 2},                                   # no domain -> global
        {"option-data": [{"name": "domain-name", "data": "x"}]},  # no id -> skipped
    ], "shared-networks": [{"subnet4": [
        {"id": 5, "option-data": [{"name": "domain-name", "data": "guest.lan"}]}]}]}
    m = S.suffix_by_subnet_id(root, "subnet4", "home.lan")
    assert m == {1: "iot.lan", 2: "home.lan", 5: "guest.lan"}
