# Testing

This plugin is tested well beyond unit level — including a full migration onto a live
production network with real DHCP clients, which surfaced (and fixed) several bugs
only visible under real traffic.

## Unit tests

`tests/unit/` — pure-Python, no OPNsense box required (the repo's `tests/conftest.py`
wires up the import path):

```sh
pytest tests/unit/
```

On the firewall itself there's no `pytest`, so the same tests are driven by a small
standalone shim (see `PLAN.md` for the harness). Coverage:

- **`test_records.py`** — record logic and the static/reserved guards.
- **`test_kea_source.py`** — dynamic-lease derivation and single-fetch clean inputs.
- **`test_config_sync.py`** — Kea config injection, including the `dhcp-ddns` block.
- **`test_unbound_io.py`** — Unbound I/O batching, pruning, and co-located static
  re-assertion.
- **`test_listener.py`** — listener guards and TSIG fail-closed behaviour.
- **`test_tsig.py`** — the TSIG helpers.
- **`test_clean.py`** — IP-based staleness.
- **`test_start.py`** — the secret-out-of-argv start wiring and spawn verification.
- **`test_stop.py`** — daemon-supervisor recognition (via `procstat`) and the orphan
  sweep.

## Live integration suite

`tests/integration/` — run against a real OPNsense box with Kea + Unbound. End-to-end
scenarios (A1–A19, plus daemon-respawn and Unbound-restart checks):

| Test | Scenario |
|---|---|
| **A1–A3** | forward A/AAAA add and reverse PTR add |
| **A4–A5** | dual-stack moves: removing the A leaves the AAAA intact, and vice-versa |
| **A6** | aggressive cleanup: old IP dropped, new IP present when a host moves |
| **A7** | TSIG enforcement: unsigned and wrong-key updates are rejected |
| **A8** | static guard: a DDNS update for a reserved address is *not* applied and *not* written to our file |
| **A12** | family-safe ANY-deletes: a forward name-wide delete keeps both A and AAAA; a specific A delete keeps the AAAA |
| **A13** | reverse ANY-delete removes the PTR |
| **A14** | reserved A + PTR survive a DDNS delete, while non-reserved records remain removable |
| **A15** | lease add registers A + PTR; lease release removes both |
| **A16** | multiple RRsets across hosts and families |
| **A17** | v6→v4 ordering: removing the AAAA preserves the A |
| **A18** | a reserved host is *never* registered by the plugin, while a dynamic host is |
| **A19** | TSIG algorithm pinning: a valid MAC under a non-configured algorithm is rejected |
| **H** | the listener is respawned by its supervisor (new live PID) if it dies |
| **J** | records persist across an Unbound restart |

## Production test pass

The plugin was migrated onto a live production network and verified healthy:
DNS resolving, real-time updates flowing, clean start/stop/restart lifecycle, and a
clean uninstall. See `PLAN.md` for the harness details and the full production test
record.
