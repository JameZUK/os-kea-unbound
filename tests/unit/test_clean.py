import importlib.util
import pathlib

from lib import records as R

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLEAN = ROOT / "src/opnsense/scripts/keaunbound/clean.py"


def load_clean():
    spec = importlib.util.spec_from_file_location("kclean", CLEAN)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_family_of():
    m = load_clean()
    fo = m.family_of
    assert fo(R.Record("h.lan", 1, "A", "10.0.0.1")) == "4"
    assert fo(R.Record("h.lan", 1, "AAAA", "2001:db8::1")) == "6"
    # PTR family is decided by the reverse zone, not the type
    assert fo(R.Record(R.ptr_name("10.0.0.1"), 1, "PTR", "h.lan")) == "4"
    assert fo(R.Record(R.ptr_name("2001:db8::1"), 1, "PTR", "h.lan")) == "6"
    # IPv4-mapped reservation normalises to v4 -> in-addr.arpa -> family 4
    assert fo(R.Record(R.ptr_name("192.0.2.5"), 1, "PTR", "h.lan")) == "4"


def test_is_stale_record():
    m = load_clean()
    isr = m.is_stale_record
    live = {"4": {"10.0.0.5"}, "6": {"2001:db8::5"}}
    live_ptr = {R.ptr_name("10.0.0.5"), R.ptr_name("2001:db8::5")}
    prun = {"4": True, "6": True}
    keep = lambda r: False   # nothing owned

    # staleness is by ADDRESS, not name: a live IP is kept, a dead IP is pruned —
    # regardless of the record's forward name (fixes the name-divergence bug).
    assert not isr(R.Record("anything.lan", 1, "A", "10.0.0.5"), live, live_ptr, prun, keep)
    assert isr(R.Record("anything.lan", 1, "A", "10.0.0.9"), live, live_ptr, prun, keep)
    assert not isr(R.Record("h.lan", 1, "AAAA", "2001:db8::5"), live, live_ptr, prun, keep)
    assert isr(R.Record("h.lan", 1, "AAAA", "2001:db8::9"), live, live_ptr, prun, keep)
    # PTR matched by the live IP's reverse name
    assert not isr(R.Record(R.ptr_name("10.0.0.5"), 1, "PTR", "h.lan"), live, live_ptr, prun, keep)
    assert isr(R.Record(R.ptr_name("10.0.0.9"), 1, "PTR", "h.lan"), live, live_ptr, prun, keep)

    # never prune an owned (static/reserved) record, even with a dead IP
    assert not isr(R.Record("h.lan", 1, "A", "10.0.0.9"), live, live_ptr, prun, lambda r: True)
    # unconfirmed family -> never prune
    assert not isr(R.Record("h.lan", 1, "A", "10.0.0.9"), live, live_ptr, {"4": False, "6": True}, keep)
    # zero-live family ("everything vanished" signature) -> never prune
    assert not isr(R.Record("h.lan", 1, "A", "10.0.0.9"),
                   {"4": set(), "6": {"2001:db8::5"}}, live_ptr, prun, keep)


def test_clean_main_prunes_only_stale_ip(tmp_path, monkeypatch):
    # End-to-end main(): IP-based pruning via clean_inputs, single fetch. A record
    # whose IP is a live lease is kept (even a v6 family that is confirmed-empty
    # keeps its records); a record whose IP is gone is pruned.
    # (Use monkeypatch — m.kea_source is the SHARED lib module; a direct assignment
    # would leak into other tests.)
    m = load_clean()
    monkeypatch.setattr(m.kea_source, "load_settings", lambda *a, **k: {"suffix": "lan"})
    monkeypatch.setattr(m.kea_source, "clean_inputs",
                        lambda: ({"4": {"10.0.0.5"}, "6": set()}, {"4": True, "6": True}))
    inc = tmp_path / "keaunbound.conf"
    inc.write_text(
        'local-data: "live.lan. 3600 IN A 10.0.0.5"\n'                       # live -> keep
        'local-data: "stale.lan. 3600 IN A 10.0.0.9"\n'                      # dead IP -> prune
        'local-data: "5.0.0.10.in-addr.arpa. 3600 IN PTR live.lan."\n'       # live PTR -> keep
        'local-data: "9.0.0.10.in-addr.arpa. 3600 IN PTR stale.lan."\n'      # dead PTR -> prune
    )
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    monkeypatch.setattr(m, "INCLUDE_FILE", str(inc))
    monkeypatch.setattr(m, "HOST_ENTRIES", str(he))
    monkeypatch.setattr(m, "UNBOUND_CONF", "/dev/null")
    monkeypatch.setattr(m, "LOG", str(tmp_path / "log"))
    rc = m.main()
    assert rc == 0
    text = inc.read_text()
    assert "10.0.0.5" in text and "5.0.0.10.in-addr.arpa" in text   # live kept
    assert "10.0.0.9" not in text and "9.0.0.10.in-addr.arpa" not in text  # stale pruned


def test_clean_main_wires_static_provider_for_coresident_statics(tmp_path, monkeypatch):
    # clean must pass a static_provider so prune's blanket local_data_remove can't
    # evict a co-located OPNsense static record of another family from runtime.
    m = load_clean()
    monkeypatch.setattr(m.kea_source, "load_settings", lambda *a, **k: {"suffix": "lan"})
    monkeypatch.setattr(m.kea_source, "clean_inputs",
                        lambda: ({"4": {"10.0.0.5"}, "6": set()}, {"4": True, "6": True}))
    inc = tmp_path / "keaunbound.conf"
    inc.write_text('local-data: "dual.lan. 3600 IN A 10.0.0.5"\n')
    he = tmp_path / "host_entries.conf"
    he.write_text('local-data: "dual.lan. 3600 IN AAAA 2001:db8::9"\n')  # co-located static
    monkeypatch.setattr(m, "INCLUDE_FILE", str(inc))
    monkeypatch.setattr(m, "HOST_ENTRIES", str(he))
    monkeypatch.setattr(m, "UNBOUND_CONF", "/dev/null")
    monkeypatch.setattr(m, "LOG", str(tmp_path / "log"))
    captured = {}
    real_zone = m.UnboundZone

    def fake_zone(*a, **k):
        captured["sp"] = k.get("static_provider")
        return real_zone(*a, **k)
    monkeypatch.setattr(m, "UnboundZone", fake_zone)
    m.main()
    sp = captured.get("sp")
    assert sp is not None
    recs = sp("dual.lan.")
    assert any(r.rtype == "AAAA" and r.rdata == "2001:db8::9" for r in recs)
