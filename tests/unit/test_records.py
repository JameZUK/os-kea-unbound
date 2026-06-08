from lib import records as R


def test_fqdn_normalisation():
    assert R.fqdn("Host.Example.COM") == "host.example.com."
    assert R.fqdn("host.example.com.") == "host.example.com."
    assert R.fqdn("  ") == ""


def test_rrtype_for_ip():
    assert R.rrtype_for_ip("192.168.1.10") == "A"
    assert R.rrtype_for_ip("2001:db8::1") == "AAAA"


def test_ptr_name_v4_v6():
    assert R.ptr_name("192.168.1.10") == "10.1.168.192.in-addr.arpa."
    assert R.ptr_name("2001:db8::1").endswith(".ip6.arpa.")


def test_host_fqdn():
    assert R.host_fqdn("Laptop", "home.lan") == "laptop.home.lan."
    # a multi-label hostname is already qualified -> used verbatim (matches the
    # FQDN the live DDNS path writes), NOT relabelled to first-label + suffix.
    assert R.host_fqdn("host.sub.example", "home.lan") == "host.sub.example."
    assert R.host_fqdn("server.corp.com.", "home.lan") == "server.corp.com."
    assert R.host_fqdn("we!rd_chars", "home.lan") == "werdchars.home.lan."
    assert R.host_fqdn("", "home.lan") == ""
    assert R.host_fqdn("x", "") == "x."


def test_norm_ip_zone_and_mapped():
    # IPv6 zone/scope id is stripped before comparison
    assert R._norm_ip("fe80::1%igb0") == "fe80::1"
    # IPv4-mapped IPv6 collapses to the v4 form so lease/reservation forms match
    assert R._norm_ip("::ffff:192.0.2.5") == "192.0.2.5"
    assert R._norm_ip("2001:DB8::0:1") == "2001:db8::1"
    assert R._norm_ip("not-an-ip") is None
    assert R._norm_ip(None) is None


def test_norm_ip_mapped_matches_reservation(tmp_path):
    import json
    p4 = tmp_path / "kea-dhcp4.conf"
    p4.write_text(json.dumps({"Dhcp4": {"reservations": [
        {"hostname": "h", "ip-address": "192.0.2.5"}]}}))
    g = R.StaticGuard(str(tmp_path / "he.conf"), [str(p4)])
    # a lease reported in IPv4-mapped form must still match the v4 reservation
    assert g.is_reserved_addr("::ffff:192.0.2.5")


def test_reserved_ips_missing_vs_unreadable(tmp_path):
    # missing config -> empty set (that family simply has no reservations)
    assert R.reserved_ips_from_config(str(tmp_path / "absent.conf")) == set()
    # present but unparseable -> raises (so callers don't read "couldn't" as "none")
    bad = tmp_path / "bad.conf"
    bad.write_text('{ this is not json')
    import pytest
    with pytest.raises(R.ReservedConfigError):
        R.reserved_ips_from_config(str(bad))


def test_static_guard_tolerates_unreadable_kea_config(tmp_path):
    # a momentarily-unreadable Kea config must not break the guard (host_entries
    # is the primary source); it just contributes no reserved IPs.
    bad = tmp_path / "bad.conf"
    bad.write_text("{ partial")
    g = R.StaticGuard(str(tmp_path / "he.conf"), [str(bad)])
    assert not g.is_reserved_addr("10.0.0.1")


def test_is_reverse_name():
    assert R.is_reverse_name("10.1.168.192.in-addr.arpa")
    assert R.is_reverse_name(R.ptr_name("2001:db8::1"))
    assert not R.is_reverse_name("host.example.com")


def test_record_lines_and_key():
    rec = R.Record("Host.Example.com", 3600, "a", "192.168.1.10")
    assert rec.local_data_line() == 'local-data: "host.example.com. 3600 IN A 192.168.1.10"'
    assert rec.control_args() == ["host.example.com. 3600 IN A 192.168.1.10"]
    # ttl excluded from identity
    assert rec.key() == R.Record("host.example.com", 60, "A", "192.168.1.10").key()


def test_ptr_record_rdata_is_fqdn():
    rec = R.Record("10.1.168.192.in-addr.arpa", 3600, "PTR", "host.example.com")
    assert rec.rdata == "host.example.com."


def test_parse_local_data_lines():
    text = (
        '# comment\n'
        'local-data: "host.example.com. 3600 IN A 192.168.1.10"\n'
        'local-data: "host.example.com 3600 IN AAAA 2001:db8::1"\n'
        'local-data-ptr: "192.168.1.10 3600 host.example.com."\n'
        'garbage line\n'
    )
    recs = R.parse_local_data_lines(text)
    assert len(recs) == 3
    types = sorted(r.rtype for r in recs)
    assert types == ["A", "AAAA", "PTR"]
    ptr = next(r for r in recs if r.rtype == "PTR")
    assert ptr.name == "10.1.168.192.in-addr.arpa."


def test_static_guard_independent_forward_and_ptr(tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text(
        'local-data: "gateway.example.com. 3600 IN A 10.10.3.10"\n'
        'local-data-ptr: "10.10.3.10 3600 gateway.example.com."\n'
    )
    g = R.StaticGuard(str(he))
    # forward A for gateway is static
    assert g.is_static_forward("gateway.example.com", "A")
    # but an unrelated AAAA for the same name is NOT static
    assert not g.is_static_forward("gateway.example.com", "AAAA")
    # PTR for that IP is static (guard stores the reversed name, as the daemon sends)
    assert g.is_static_ptr(R.ptr_name("10.10.3.10"))  # 10.3.10.10.in-addr.arpa.
    # a different host's forward is not blocked by the PTR (issue #11 regression)
    assert not g.is_static_forward("laptop.example.com", "A")


def test_static_guard_missing_file(tmp_path):
    g = R.StaticGuard(str(tmp_path / "nope.conf"))
    assert not g.is_static_forward("anything.example.com", "A")
    assert not g.is_static_ptr("1.2.3.4.in-addr.arpa")


def test_reserved_ips_from_config(tmp_path):
    import json
    p4 = tmp_path / "kea-dhcp4.conf"
    p4.write_text(json.dumps({"Dhcp4": {
        "subnet4": [{"subnet": "10.10.3.0/24", "reservations": [
            {"hostname": "host-a", "ip-address": "10.10.3.20"}]}],
        "shared-networks": [{"subnet4": [{"subnet": "10.10.4.0/24", "reservations": [
            {"hostname": "host-b", "ip-address": "10.10.4.9"}]}]}],
        "reservations": [{"hostname": "host-g", "ip-address": "10.10.3.5"}],  # global
    }}))
    p6 = tmp_path / "kea-dhcp6.conf"
    p6.write_text(json.dumps({"Dhcp6": {"subnet6": [
        {"subnet": "2001:db8::/64", "reservations": [
            {"hostname": "host-6", "ip-addresses": ["2001:db8::20"]}]}]}}))
    ips = R.reserved_ips_from_config(str(p4)) | R.reserved_ips_from_config(str(p6))
    assert ips == {"10.10.3.20", "10.10.4.9", "10.10.3.5", "2001:db8::20"}


def test_reservation_guard(tmp_path):
    import json
    p4 = tmp_path / "kea-dhcp4.conf"
    p4.write_text(json.dumps({"Dhcp4": {"subnet4": [
        {"subnet": "10.10.3.0/24", "reservations": [
            {"hostname": "printer", "ip-address": "10.10.3.20"}]}]}}))
    p6 = tmp_path / "kea-dhcp6.conf"
    p6.write_text(json.dumps({"Dhcp6": {"subnet6": [
        {"subnet": "2001:db8::/64", "reservations": [
            {"hostname": "nas", "ip-addresses": ["2001:db8::20"]}]}]}}))
    g = R.StaticGuard(str(tmp_path / "host_entries.conf"), [str(p4), str(p6)])
    # the reserved IP is protected, by address and by its PTR name (v4 + v6)
    assert g.is_reserved_addr("10.10.3.20")
    assert g.is_reserved_addr("2001:DB8:0:0:0:0:0:20")   # canonicalised v6 match
    assert g.is_reserved_ptr(R.ptr_name("10.10.3.20"))
    assert g.is_reserved_ptr(R.ptr_name("2001:db8::20"))
    # unrelated addresses / names are not
    assert not g.is_reserved_addr("10.10.3.99")
    assert not g.is_reserved_ptr(R.ptr_name("10.10.3.99"))
    assert not g.is_reserved_addr("not-an-ip")


def test_reservation_guard_no_kea_paths(tmp_path):
    # backward-compatible: no kea paths -> nothing reserved
    g = R.StaticGuard(str(tmp_path / "host_entries.conf"))
    assert not g.is_reserved_addr("10.10.3.20")
    assert not g.is_reserved_ptr("20.3.10.10.in-addr.arpa.")
