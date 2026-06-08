from lib import records as R
from lib.unbound_io import UnboundZone


class FakeRunner:
    """Records unbound-control invocations (args + stdin) and always succeeds."""

    def __init__(self):
        self.calls = []   # list of (args, input)

    def __call__(self, args, input=None):
        self.calls.append((list(args), input))
        return 0, ""

    def added(self):
        """All record lines pushed via batched `local_datas` (stdin)."""
        out = []
        for args, inp in self.calls:
            if args == ["local_datas"] and inp:
                out += [ln for ln in inp.splitlines() if ln]
        return out

    def removed_names(self):
        return [args[1] for args, _ in self.calls if args[0] == "local_data_remove"]


def make_zone(tmp_path):
    runner = FakeRunner()
    inc = tmp_path / "keaunbound.conf"
    zone = UnboundZone(include_file=str(inc), unbound_conf="/dev/null",
                       runner=runner, lock_path=str(tmp_path / "lock"))
    return zone, runner, inc


def test_add_writes_file_and_runtime(tmp_path):
    zone, runner, inc = make_zone(tmp_path)
    assert zone.add(R.Record("host.example.com", 3600, "A", "192.168.1.10"))
    assert 'local-data: "host.example.com. 3600 IN A 192.168.1.10"' in inc.read_text()
    # reconcile = remove the name then batch-re-add its records via local_datas
    assert "host.example.com." in runner.removed_names()
    assert "host.example.com. 3600 IN A 192.168.1.10" in runner.added()


def test_idempotent_add(tmp_path):
    zone, runner, inc = make_zone(tmp_path)
    rec = R.Record("host.example.com", 3600, "A", "192.168.1.10")
    assert zone.add(rec) is True
    assert zone.add(R.Record("host.example.com", 3600, "A", "192.168.1.10")) is False


def test_dual_stack_preservation_on_delete(tmp_path):
    zone, runner, inc = make_zone(tmp_path)
    zone.add(R.Record("host.example.com", 3600, "A", "192.168.1.10"))
    zone.add(R.Record("host.example.com", 3600, "AAAA", "2001:db8::1"))
    runner.calls.clear()
    # delete the A record
    assert zone.remove("host.example.com", "A", "192.168.1.10")
    text = inc.read_text()
    assert "IN A 192.168.1.10" not in text
    assert "IN AAAA 2001:db8::1" in text          # sibling preserved in file
    # runtime reconcile wiped the name then re-added the surviving AAAA (batched)
    assert "host.example.com." in runner.removed_names()
    assert "host.example.com. 3600 IN AAAA 2001:db8::1" in runner.added()


def test_remove_other_addresses(tmp_path):
    zone, runner, inc = make_zone(tmp_path)
    zone.add(R.Record("host.example.com", 3600, "A", "192.168.1.10"))
    zone.add(R.Record("10.1.168.192.in-addr.arpa", 3600, "PTR", "host.example.com"))
    removed = zone.remove_other_addresses("host.example.com", "A", "192.168.1.99")
    assert removed == ["192.168.1.10"]
    text = inc.read_text()
    assert "192.168.1.10" not in text            # old forward gone
    assert "10.1.168.192.in-addr.arpa" not in text  # its PTR gone too


def test_persistence_reload(tmp_path):
    zone, runner, inc = make_zone(tmp_path)
    zone.add(R.Record("host.example.com", 3600, "A", "192.168.1.10"))
    # a fresh zone object loads the same records from the include file
    zone2, _, _ = make_zone(tmp_path)
    assert len(zone2._records_for("host.example.com")) == 1
