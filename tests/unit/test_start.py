"""The TSIG secret must travel via the environment, never the daemon argv (argv is
world-readable via ps(1) / /proc/<pid>/cmdline)."""
import importlib.util
import pathlib
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
START = ROOT / "src/opnsense/scripts/keaunbound/start.py"


def load_start():
    spec = importlib.util.spec_from_file_location("kstart", START)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_secret_not_in_argv_but_in_env():
    m = load_start()
    gen = ET.fromstring(
        "<general><enabled>1</enabled><listener_port>53535</listener_port>"
        "<tsig_enabled>1</tsig_enabled><tsig_key_name>keaunbound</tsig_key_name>"
        "<tsig_key_secret>S3cRET/base64==</tsig_key_secret>"
        "<tsig_algorithm>hmac-sha256</tsig_algorithm>"
        "<aggressive_cleanup>1</aggressive_cleanup></general>"
    )
    args = m.build_args(gen, "lan")
    assert "--tsig-secret" not in args
    assert "S3cRET/base64==" not in args          # secret nowhere in argv
    assert "--tsig-name" in args and "--tsig-algorithm" in args
    assert m.tsig_secret_env(gen).get("KEAUNBOUND_TSIG_SECRET") == "S3cRET/base64=="


def test_no_tsig_no_secret_env():
    m = load_start()
    gen = ET.fromstring("<general><enabled>1</enabled><tsig_enabled>0</tsig_enabled></general>")
    args = m.build_args(gen, "lan")
    assert "--no-tsig" in args
    assert "KEAUNBOUND_TSIG_SECRET" not in m.tsig_secret_env(gen)


def test_spawn_and_verify_returns_true_when_listener_comes_up(monkeypatch):
    m = load_start()
    monkeypatch.setattr(m, "_spawn", lambda gen, domain: None)
    monkeypatch.setattr(m, "_listener_up", lambda: True)
    assert m._spawn_and_verify(None, "lan", timeout=1.0) is True


def test_spawn_and_verify_returns_false_when_nothing_binds(monkeypatch):
    # The configd-start flake / a fail-closed exit leaves no listener — verify must
    # detect that rather than report success.
    m = load_start()
    monkeypatch.setattr(m, "_spawn", lambda gen, domain: None)
    monkeypatch.setattr(m, "_listener_up", lambda: False)
    assert m._spawn_and_verify(None, "lan", timeout=0.1) is False


def test_listener_up_false_on_missing_pidfile(monkeypatch, tmp_path):
    m = load_start()
    monkeypatch.setattr(m, "PIDFILE", str(tmp_path / "nope.pid"))
    assert m._listener_up() is False
