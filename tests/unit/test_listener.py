"""Unit tests for the listener's dynamic-only / static-reserved guard gating in
_add and _delete (the core safety invariants). No dnspython/socket needed — these
methods operate on the UnboundZone + StaticGuard only; the runtime runner is stubbed."""
import importlib.util
import json
import os
import pathlib
import types

ROOT = pathlib.Path(__file__).resolve().parents[2]
DAEMON = ROOT / "src/sbin/kea-unbound-ddns.py"


def load_daemon():
    spec = importlib.util.spec_from_file_location("kud", DAEMON)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def make_listener(tmp_path, aggressive=False, host_entries="", kea_confs=()):
    he = tmp_path / "host_entries.conf"
    he.write_text(host_entries)
    args = types.SimpleNamespace(
        include_file=str(tmp_path / "keaunbound.conf"),
        unbound_conf="/dev/null",
        host_entries=str(he),
        kea_conf=list(kea_confs),
        bind="127.0.0.1",
        no_tsig=True, tsig_secret="", tsig_name="keaunbound", tsig_algorithm="hmac-sha256",
        aggressive_cleanup=aggressive,
    )
    lis = load_daemon().Listener(args)
    lis.zone.runner = lambda a, input=None: (0, "")   # never call real unbound-control
    return lis, args


def filetext(args):
    try:
        return open(args.include_file).read()
    except OSError:
        return ""


def test_add_dynamic_forward_written(tmp_path):
    lis, args = make_listener(tmp_path)
    lis._add("dyn.lan.", 3600, "A", "10.0.0.9")
    assert 'dyn.lan. 3600 IN A 10.0.0.9' in filetext(args)


def test_add_skips_static_forward(tmp_path):
    he = 'local-data: "static.lan. 3600 IN A 10.0.0.5"\n'
    lis, args = make_listener(tmp_path, host_entries=he)
    lis._add("static.lan.", 3600, "A", "10.0.0.5")
    assert "10.0.0.5" not in filetext(args)   # OPNsense owns it; never written


def test_add_skips_reserved_ip(tmp_path):
    k4 = tmp_path / "k4.conf"
    k4.write_text(json.dumps({"Dhcp4": {"reservations": [
        {"hostname": "r", "ip-address": "10.0.0.50"}]}}))
    lis, args = make_listener(tmp_path, kea_confs=[str(k4)])
    lis._add("resv.lan.", 3600, "A", "10.0.0.50")   # reserved IP
    assert "10.0.0.50" not in filetext(args)
    lis._add("ok.lan.", 3600, "A", "10.0.0.51")     # dynamic
    assert "10.0.0.51" in filetext(args)


def test_add_skips_static_ptr(tmp_path):
    ptr = "5.0.0.10.in-addr.arpa."
    he = 'local-data-ptr: "10.0.0.5 3600 static.lan"\n'
    lis, args = make_listener(tmp_path, host_entries=he)
    lis._add(ptr, 3600, "PTR", "something.lan.")
    assert "in-addr.arpa" not in filetext(args)


def test_delete_skips_static(tmp_path):
    # even if a record somehow sits at a static name, _delete must not evict it
    he = 'local-data: "static.lan. 3600 IN A 10.0.0.5"\n'
    lis, args = make_listener(tmp_path, host_entries=he)
    lis.zone.add(load_daemon().R.Record("static.lan.", 3600, "A", "10.0.0.5"))
    lis._delete("static.lan.", "A", "10.0.0.5")
    assert "10.0.0.5" in filetext(args)   # guard prevented removal


def test_delete_removes_dynamic(tmp_path):
    lis, args = make_listener(tmp_path)
    lis._add("dyn.lan.", 3600, "A", "10.0.0.9")
    lis._delete("dyn.lan.", "A", "10.0.0.9")
    assert "10.0.0.9" not in filetext(args)


def _tsig_args(tmp_path, no_tsig, secret, bind="127.0.0.1"):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    return types.SimpleNamespace(
        include_file=str(tmp_path / "keaunbound.conf"), unbound_conf="/dev/null",
        host_entries=str(he), kea_conf=[], bind=bind, no_tsig=no_tsig, tsig_secret=secret,
        tsig_name="keaunbound", tsig_algorithm="hmac-sha256", aggressive_cleanup=False)


def test_tsig_required_without_secret_fails_closed(tmp_path):
    # TSIG required (not --no-tsig) but no secret anywhere -> refuse to start,
    # never silently downgrade to accepting unsigned updates.
    import os
    import pytest
    old = os.environ.pop("KEAUNBOUND_TSIG_SECRET", None)
    try:
        with pytest.raises(SystemExit):
            load_daemon().Listener(_tsig_args(tmp_path, no_tsig=False, secret=""))
    finally:
        if old is not None:
            os.environ["KEAUNBOUND_TSIG_SECRET"] = old


def test_tsig_required_with_env_secret_builds_keyring(tmp_path):
    try:
        import dns.tsigkeyring  # noqa: F401
    except ImportError:
        return  # off-box: no dnspython
    import os
    old = os.environ.get("KEAUNBOUND_TSIG_SECRET")
    os.environ["KEAUNBOUND_TSIG_SECRET"] = "YWJjZA=="
    try:
        lis = load_daemon().Listener(_tsig_args(tmp_path, no_tsig=False, secret=""))
        lis.zone.runner = lambda a, input=None: (0, "")
        assert lis.keyring is not None and lis.keyalgo == "hmac-sha256"
    finally:
        if old is None:
            os.environ.pop("KEAUNBOUND_TSIG_SECRET", None)
        else:
            os.environ["KEAUNBOUND_TSIG_SECRET"] = old


def test_no_tsig_runs_without_keyring(tmp_path):
    # explicit --no-tsig on loopback: no keyring, no fail-closed (user disabled TSIG)
    lis = load_daemon().Listener(_tsig_args(tmp_path, no_tsig=True, secret=""))
    assert lis.keyring is None and lis.tsig_required is False


def test_is_loopback():
    m = load_daemon()
    assert m._is_loopback("127.0.0.1") and m._is_loopback("127.0.0.5") and m._is_loopback("::1")
    assert not m._is_loopback("0.0.0.0") and not m._is_loopback("192.168.1.1")
    assert not m._is_loopback("not-an-ip")


def test_no_tsig_nonloopback_refused(tmp_path):
    # --no-tsig + a non-loopback bind would expose unauthenticated DNS-write to the
    # network — must fail closed.
    import pytest
    with pytest.raises(SystemExit):
        load_daemon().Listener(_tsig_args(tmp_path, no_tsig=True, secret="", bind="0.0.0.0"))


def test_no_tsig_loopback_allowed(tmp_path):
    lis = load_daemon().Listener(_tsig_args(tmp_path, no_tsig=True, secret="", bind="127.0.0.1"))
    assert lis.keyring is None


def test_coresident_static_reasserted_on_dynamic_add(tmp_path):
    # A host with an OPNsense static AAAA that also gets a dynamic A: the dynamic A
    # is written, and the runtime reconcile must RE-ASSERT the static AAAA (the
    # blanket local_data_remove would otherwise evict it from the running resolver).
    he = 'local-data: "dual.lan. 3600 IN AAAA 2001:db8::9"\n'
    lis, args = make_listener(tmp_path, host_entries=he)
    calls = []
    lis.zone.runner = lambda a, input=None: (calls.append((list(a), input)) or (0, ""))
    lis._add("dual.lan.", 3600, "A", "10.0.0.9")
    added = "".join(inp for a, inp in calls if a == ["local_datas"] and inp)
    assert "dual.lan. 3600 IN A 10.0.0.9" in added       # our dynamic record
    assert "dual.lan. 3600 IN AAAA 2001:db8::9" in added  # static AAAA preserved in runtime


# ---- issue #28: PTR target guard ------------------------------------------
STATIC_LDAP = ('local-data: "ldap.example.lan. 3600 IN A 10.0.0.5"\n'
               'local-data-ptr: "10.0.0.5 3600 ldap.example.lan"\n')


def test_add_skips_ptr_to_static_name(tmp_path):
    # A dynamic client claiming a reserved host's name: its A is refused, and so
    # must its PTR be, or its IP reverse-resolves to the reserved host.
    lis, args = make_listener(tmp_path, host_entries=STATIC_LDAP)
    lis._add("ldap.example.lan.", 2400, "A", "10.0.0.100")
    lis._add("100.0.0.10.in-addr.arpa.", 2400, "PTR", "ldap.example.lan.")
    assert filetext(args).strip() == ""


def test_add_ptr_to_dynamic_name_still_written(tmp_path):
    lis, args = make_listener(tmp_path, host_entries=STATIC_LDAP)
    lis._add("100.0.0.10.in-addr.arpa.", 2400, "PTR", "laptop.example.lan.")
    assert "100.0.0.10.in-addr.arpa. 2400 IN PTR laptop.example.lan." in filetext(args)


# ---- issue #29: honour D2's reverse-removal prerequisite --------------------
REV = "100.0.0.10.in-addr.arpa."


def test_reverse_delete_keeps_ptr_that_names_a_newer_lease(tmp_path):
    # Old lease (foo) removal arrives after the new lease (bar) added its PTR on the
    # same IP: the prerequisite says "PTR -> foo", so bar's PTR must survive.
    lis, args = make_listener(tmp_path)
    lis._add(REV, 2400, "PTR", "bar.example.lan.")
    lis._delete(REV, "ANY", None, {"foo.example.lan."})
    assert f"{REV} 2400 IN PTR bar.example.lan." in filetext(args)


def test_reverse_delete_removes_ptr_matching_prerequisite(tmp_path):
    lis, args = make_listener(tmp_path)
    lis._add(REV, 2400, "PTR", "foo.example.lan.")
    lis._delete(REV, "ANY", None, {"FOO.example.lan."})
    assert REV not in filetext(args)


def test_reverse_delete_without_prerequisite_is_name_wide(tmp_path):
    # Senders that carry no prerequisite keep the old behaviour.
    lis, args = make_listener(tmp_path)
    lis._add(REV, 2400, "PTR", "foo.example.lan.")
    lis._delete(REV, "ANY", None)
    assert REV not in filetext(args)


class _Sock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def _d2_reverse_add(fqdn):
    """kea-dhcp-ddns NameAddTransaction::buildReplaceRevPtrsRequest: no
    prerequisite; delete PTR + DHCID RRsets, then add PTR + DHCID."""
    import dns.update
    u = dns.update.UpdateMessage("in-addr.arpa.")
    u.delete(REV, "PTR")
    u.delete(REV, "DHCID")
    u.add(REV, 2400, "PTR", fqdn)
    u.add(REV, 2400, "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=")
    return u.to_wire()


def _d2_reverse_remove(fqdn):
    """kea-dhcp-ddns NameRemoveTransaction::buildRemoveRevPtrsRequest: prerequisite
    `<rev> IN PTR <fqdn>`, then delete all RRsets at the reverse name."""
    import dns.update
    u = dns.update.UpdateMessage("in-addr.arpa.")
    u.present(REV, "PTR", fqdn)
    u.delete(REV)
    return u.to_wire()


def test_handle_out_of_order_d2_reverse_remove_keeps_new_ptr(tmp_path):
    # End to end through handle() with D2-shaped wire messages: the issue #29 order
    # (new lease's add first, old lease's removal a moment later).
    import pytest
    pytest.importorskip("dns.update")
    lis, args = make_listener(tmp_path)
    sock = _Sock()
    lis.handle(_d2_reverse_add("foo.example.lan."), ("127.0.0.1", 1), sock)
    lis.handle(_d2_reverse_add("bar.example.lan."), ("127.0.0.1", 1), sock)
    lis.handle(_d2_reverse_remove("foo.example.lan."), ("127.0.0.1", 1), sock)
    text = filetext(args)
    assert f"{REV} 2400 IN PTR bar.example.lan." in text
    assert "foo.example.lan." not in text
    assert len(sock.sent) == 3   # every UPDATE still acknowledged (NOERROR)


def test_handle_d2_reverse_remove_for_current_lease(tmp_path):
    import pytest
    pytest.importorskip("dns.update")
    lis, args = make_listener(tmp_path)
    sock = _Sock()
    lis.handle(_d2_reverse_add("foo.example.lan."), ("127.0.0.1", 1), sock)
    lis.handle(_d2_reverse_remove("foo.example.lan."), ("127.0.0.1", 1), sock)
    assert REV not in filetext(args)
