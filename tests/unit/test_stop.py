"""stop.py must recognise and kill the daemon(8) supervisor even though daemon(8)
retitles itself ('daemon: python3[child] (daemon)') and so cannot be matched by the
script path in its OWN command line. Identify it by its child; without this an
orphaned supervisor survives stop/teardown/uninstall and respawns the listener."""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
STOP = ROOT / "src/opnsense/scripts/keaunbound/stop.py"

SUP, CHILD = 42563, 44354   # supervisor PID, listener child PID (as seen on-box)


def load_stop():
    spec = importlib.util.spec_from_file_location("kstop", STOP)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_supervisor_recognised_by_its_child(monkeypatch):
    m = load_stop()
    monkeypatch.setattr(m, "_alive", lambda pid: pid in (SUP, CHILD))
    monkeypatch.setattr(m, "_is_ours", lambda pid: pid == CHILD)
    monkeypatch.setattr(m, "_pgrep", lambda *a: [CHILD] if a == ("-P", str(SUP)) else [])
    assert m._is_ours(SUP) is False          # retitled: its own command can't match
    assert m._is_our_supervisor(SUP) is True  # but its child is ours
    assert m._ours(SUP) is True               # so the combined check signals it


def test_ours_never_trusts_bare_provenance(monkeypatch):
    """A daemon(8) that is NOT supervising our listener must never be considered ours,
    even at a recorded supervisor pid — otherwise PID reuse lets stop kill an unrelated
    service. _ours requires identity via the child, not provenance."""
    m = load_stop()
    monkeypatch.setattr(m, "_is_ours", lambda pid: False)
    monkeypatch.setattr(m, "_is_our_supervisor", lambda pid: False)
    assert m._ours(123) is False


def test_sweep_kills_orphan_supervisor_and_child(monkeypatch):
    m = load_stop()
    killed = []
    monkeypatch.setattr(m, "_alive", lambda pid: True)
    monkeypatch.setattr(m, "_is_ours", lambda pid: pid == CHILD)

    def pg(*a):
        if a == ("-x", "daemon"):
            return [SUP]
        if a == ("-P", str(SUP)):
            return [CHILD]
        return []
    monkeypatch.setattr(m, "_pgrep", pg)
    monkeypatch.setattr(m, "_listener_pids", lambda: [CHILD])
    monkeypatch.setattr(m.os, "kill", lambda pid, sig: killed.append(pid))
    m._sweep_orphans()
    assert SUP in killed and CHILD in killed


def test_is_ours_rejects_lookalikes(monkeypatch):
    """_is_ours must anchor to the python+script invocation, not a bare substring,
    so a .log tail / editor / grep / the retitled supervisor itself aren't 'ours'
    (else _sweep_orphans could SIGKILL a daemon(8) parenting one of them)."""
    m = load_stop()
    monkeypatch.setattr(m, "_alive", lambda pid: True)
    cases = {
        "/usr/local/bin/python3 /usr/local/sbin/kea-unbound-ddns.py --port 53535": True,
        "tail -f /var/log/keaunbound/kea-unbound-ddns.log": False,
        "vim /tmp/kea-unbound-ddns.py": False,                  # editor, not python
        "grep kea-unbound-ddns /var/log/system.log": False,
        "daemon: /usr/local/bin/python3[44354] (daemon)": False,  # retitled supervisor
    }
    for cmd, expected in cases.items():
        monkeypatch.setattr(m, "_cmdline", lambda pid, _c=cmd: _c)
        assert m._is_ours(1234) is expected, cmd


def test_cmdline_reads_procstat_when_ps_is_empty(monkeypatch):
    """On a box with a small kern.ps_arg_cache_limit, ps returns an EMPTY argv for a
    long command line; _cmdline must fall through to procstat, which reads the kernel
    args directly. (This is the prod bug that made ps-based stop unable to see the
    listener.)"""
    m = load_stop()
    procstat_out = (
        "  PID COMM             ARGS\n"
        "19812 python3.13       /usr/local/bin/python3 /usr/local/sbin/"
        "kea-unbound-ddns.py --port 53535 --tsig-name keaunbound\n")

    class _R:
        def __init__(self, out):
            self.stdout = out

    def fake_run(cmd, **k):
        if cmd[0] == "procstat":
            return _R(procstat_out)
        return _R("")          # ps yields nothing (the cache-limit scenario)
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    out = m._cmdline(19812)
    assert "kea-unbound-ddns.py" in out and "python" in out
    assert m._cmdline(99999) == ""   # pid not present -> empty (then empty ps)


def test_listener_pids_excludes_mere_mentions(monkeypatch):
    """_listener_pids must return only real listeners, never a grep/awk/editor whose
    argv merely MENTIONS the script path (procstat -ac would otherwise include them)."""
    m = load_stop()
    ac = ("19812 python3.13 /usr/local/bin/python3 /usr/local/sbin/kea-unbound-ddns.py --port 53535\n"
          "65169 grep grep -c kea-unbound-ddns.py\n"
          "12345 python3.13 /usr/local/bin/python3 /usr/local/opnsense/service/configd.py\n")
    perpid = {
        19812: "19812 python3.13 /usr/local/bin/python3 /usr/local/sbin/kea-unbound-ddns.py --port 53535",
        65169: "65169 grep grep -c kea-unbound-ddns.py",
    }

    class _R:
        def __init__(self, out):
            self.stdout = out

    def fake_run(cmd, **k):
        if cmd[:2] == ["procstat", "-ac"]:
            return _R(ac)
        if cmd[0] == "procstat":
            return _R((perpid.get(int(cmd[2]), "") + "\n"))
        return _R("")
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    monkeypatch.setattr(m, "_alive", lambda pid: True)
    pids = m._listener_pids()
    assert 19812 in pids and 65169 not in pids and 12345 not in pids


def test_sweep_leaves_foreign_daemons_alone(monkeypatch):
    m = load_stop()
    killed = []
    monkeypatch.setattr(m, "_alive", lambda pid: True)
    monkeypatch.setattr(m, "_is_ours", lambda pid: False)  # nothing here is ours

    def pg(*a):
        if a == ("-x", "daemon"):
            return [999]       # some unrelated daemon(8) supervisor
        if a == ("-P", "999"):
            return [1000]      # whose child is not our listener
        return []
    monkeypatch.setattr(m, "_pgrep", pg)
    monkeypatch.setattr(m.os, "kill", lambda pid, sig: killed.append(pid))
    m._sweep_orphans()
    assert killed == []
