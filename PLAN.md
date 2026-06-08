# os-kea-unbound — DDNS-listener rewrite (v0.x)

Living design doc for the `feature/ddns-listener` branch. The goal is to replace
the v3.8.x approach (which patches Kea's MVC/PHP files at install time) with a
clean standalone OPNsense plugin that needs no core-file patching.

## Why

The v3.8.x line works and is production-hardened, but its core liability is that
it edits files owned by the Kea package. The entire repair-hook / signature-strip
/ `.bak` machinery exists only to survive that fragility. This rewrite removes the
fragility at the source.

Inspired by tkreagan's fork (https://github.com/tkreagan/os-kea-unbound), which
proved the DDNS-listener architecture. We adopt that approach and add: fully
automated global DDNS config (no per-subnet clicking), auto-provisioned TSIG, and
config-include persistence.

## Architecture (finalized)

Two paths, no Kea-file patching:

- **Dynamic (real-time):** Kea's native `kea-dhcp-ddns` (D2) sends RFC 2136 DNS
  UPDATE packets to our loopback listener, which applies them to Unbound.
- **Static/initial:** on enable/start we read existing Kea leases + reservations
  via the Kea Control Agent (KCA) socket and seed Unbound.

### How records reach Unbound — hybrid persistence

- **Runtime:** `unbound-control local_data` / `local_data_remove` for immediate
  effect (no waiting for an Unbound restart).
- **Persistence:** mirror every record into `/var/unbound/etc/keaunbound.conf`,
  which OPNsense's generated `unbound.conf` always pulls in via
  `include: /var/unbound/etc/*.conf`. Records therefore survive every Unbound
  restart automatically — no repopulation hook, no polling. (This is exactly how
  OPNsense's own host_entries.conf / dhcpleases.conf work.)

### The trigger (verified against opnsense/core)

- OPNsense wires Kea config generation into an rc precmd:
  `kea_setup="/usr/local/sbin/pluginctl -c kea_sync"`, run on every `kea start`
  (GUI Apply force-restarts, so this fires on every apply, boot, and manual
  restart).
- `pluginctl -c kea_sync` runs every plugin's `kea_sync` hook in `.inc`
  filename order. `kea.inc` (`kea_configure_do`) generates the configs first;
  our `keaunbound.inc` sorts after `kea`, so **our injector runs after the
  configs are generated and before the daemon starts** — one clean restart, no
  watcher, no double-restart, self-healing.
- Residual unknown (medium-high confidence): the port-supplied
  `/usr/local/etc/rc.d/kea` body couldn't be read; the "precmd strictly before
  daemon" timing is by FreeBSD rc convention. Verify on the test box in Phase 4.

### What the injector does (`kea_sync` hook)

Runs after `kea_configure_do`, edits the just-generated files in place
(idempotent + atomic):

- `kea-dhcp{4,6}.conf`: add top-level `ddns-send-updates: true` +
  `ddns-qualifying-suffix`, plus `ddns-replace-client-name: when-not-present` +
  `ddns-generated-prefix` (the DDNS-native equivalent of v3.8's MAC/DUID
  smart-hostnames).
- `kea-dhcp-ddns.conf`: replace `ddns-domains` with a catch-all (forward `.`,
  reverse `in-addr.arpa.` / `ip6.arpa.`) pointing at `127.0.0.1:<listener_port>`,
  with the TSIG key attached.

### D2 enablement

On plugin enable we set `Kea/ddns/general/enabled = 1` in config.xml (with a
marker so uninstall reverts only what we set) and trigger a Kea reconfigure, so
`keactrl` launches D2. Zero Kea-GUI interaction.

### TSIG

Auto-generated HMAC-SHA256 key, created once on enable, stored in our model,
written into D2 (so D2 signs) and loaded by the listener (so it verifies). On by
default; defends against other local processes injecting records into the
loopback listener.

## Decisions (locked)

- Qualifying suffix: one global setting, default = box domain.
- Ports: defaults only (D2 NCR channel 53001 as OPNsense sets it; listener 53535).
- Static sync source: KCA control socket (primary), Kea memfile CSV (fallback).
- Repopulation: config-include persistence (hybrid) — NOT an event hook (Unbound
  has no reliable post-restart event; Apply always full-restarts and wipes
  runtime local_data).
- Version: start at 0.1.
- Package name: keep `os-kea-unbound`.

## Carried over from v3.8

Record logic ported into the listener: dual-stack sibling preservation on delete,
the host_entries.conf static guard (independent forward/PTR gating), PTR
computation, hostname handling. Atomic/idempotent file writes.

## Build phases

- [x] **0 — Scaffolding & packaging** (Makefile, pkg-descr, plugin tree, ACL, menu)
- [x] **1 — Settings model + UI** (General model/controller/view, TSIG key gen)
- [x] **2 — Listener engine** (RFC 2136 + TSIG + hybrid apply + record logic; off-box unit-tested)
- [x] **3 — Service wiring** (configd actions, start/stop, daemon(8) supervision, service registration)
- [x] **4 — kea_sync injector + D2 auto-enable** (verified end-to-end on the test box)
- [x] **4.5 — config safety** (record-before-mutate + revert, non-destructive D2 merge, atomic, alerts)
- [x] **5 — static sync** (seed existing leases + reservations; control socket primary, CSV fallback, NO KCA needed) — verified on the test box
- [x] **6 — Status page** (Services → Kea Unbound DDNS → Status: listener health, record count, TSIG, Kea-DDNS ownership, recent log, "Sync now") — data verified on the test box
- [x] **7 — clean uninstall/teardown** (shared teardown.php: revert Kea DDNS iff owned, stop listener, flush records + remove include file, regenerate clean Kea; wired to the disable path AND a +PRE_DEINSTALL) — verified on the test box
- [x] **8 — audit/clean + logs + docs** (lib/kea_source shared source-of-truth; `audit`/`clean` configd actions with a Kea-reachability guard against wiping; newsyslog rotation; README rewritten) — verified on the test box
- [x] **9 — package build + lifecycle** (built a 0.1 .pkg with `pkg create`, clean install + run, and `pkg delete` ran the `+PRE_DEINSTALL` teardown with full revert; 25 unit tests pass) — verified on the test box

Phases 0–3 need no router. Phase 4 is the first on-box milestone.

### Remaining release steps (need a push / build host)
- Run the **official `make package`** on an OPNsense plugins tree (the test box has no
  git/plugins tree, so 9 was validated with a hand-built `pkg create` — the package
  STRUCTURE and lifecycle are proven; the official build adds OPNsense firmware metadata).
- Remove the retired v3.x files (`build_plugin.sh`, `healthcheck.sh`, `test_hook.sh`) from
  this line before release.
- Tag **0.1** and (optionally) set up CI to run the pytest suite.

## Layout

```
Makefile, pkg-descr
src/etc/inc/plugins.inc.d/keaunbound.inc
src/opnsense/mvc/app/models/OPNsense/KeaUnbound/{General.xml,General.php,ACL/ACL.xml,Menu/Menu.xml}
src/opnsense/mvc/app/controllers/OPNsense/KeaUnbound/{IndexController.php,Api/GeneralController.php,Api/ServiceController.php}
src/opnsense/mvc/app/views/OPNsense/KeaUnbound/index.volt
src/opnsense/mvc/app/controllers/OPNsense/KeaUnbound/forms/generalSettings.xml
src/opnsense/scripts/keaunbound/{start.py,stop.py,lib/}
src/opnsense/service/conf/actions.d/actions_keaunbound.conf
src/sbin/kea-unbound-ddns.py
tests/
```

## Empirical findings from the test box (OPNsense 26.1.9)

- Base python is **3.13** → `PLUGIN_DEPENDS=py313-dnspython` (dnspython 2.8.0 already present). 
- **Trigger confirmed:** `pluginctl -c kea_sync` regenerates the daemon configs by running
  every plugin's kea_sync hook in `.inc` filename order. `kea.inc` (kea_configure_do) runs
  first, our `keaunbound.inc` runs after → our injector lands on the fresh config. `configctl
  kea restart` alone does NOT run kea_sync, so our ServiceController reconfigure runs
  `template reload` + `kea restart` (and relies on the kea_sync pass). `template reload`
  regenerates `keactrl.conf` (dhcp4/6/ddns yes/no) + `/etc/rc.conf.d/kea`.
- **Model mount gotcha:** mount must be `//OPNsense/KeaUnbound` (NOT `.../general`), else the
  `<general>` items wrapper produces a double `general` node and config readers miss `enabled`.
- **Per-subnet override gotcha:** OPNsense emits per-subnet `ddns-send-updates: false` which
  overrides our global `true` (Kea: subnet beats global). The injector strips that false so
  subnets inherit the global value. It does NOT touch explicit per-subnet `true`.
- **Static sync (5):** `lease_cmds` is loaded by default, so `lease4/6-get-all` works on the
  per-daemon unix control socket (`/var/run/kea/kea{4,6}-ctrl-socket`) — no KCA/control-agent
  enable required. Reservations are read from the generated kea-dhcp{4,6}.conf (global +
  per-subnet). Memfile CSV (`/var/db/kea/kea-leases{4,6}.csv`) is the fallback. Run by
  `configctl keaunbound sync` and by start.py after the listener launches.
- **Teardown (7):** one routine (`teardown.php`, configd action `keaunbound teardown`) used by
  both the disable path and the package `+PRE_DEINSTALL`. plugins.mk picks up lifecycle scripts
  (`+PRE_INSTALL/+POST_INSTALL/+PRE_DEINSTALL/+POST_DEINSTALL`) from the **plugin root** (not
  src/); modern pkg runs `+PRE_DEINSTALL` on real deletion, not upgrades. Recommended uninstall
  flow is still "disable in the GUI first" (same teardown runs). The `+PRE_DEINSTALL` pkg-time
  behaviour will be re-confirmed at Phase 9 packaging (can't build a pkg without the plugins tree).
- **Config safety (4.5):** the only persistent setting we change is `Kea/ddns/general/enabled`
  (0→1). We mark `manage_kea_ddns` when WE enable it, revert on disable only if we own it, and
  never take ownership if the user already had it on. The generated-config edits are atomic
  (os.replace), self-cleaning when disabled, and the D2 injector PRESERVES any user-configured
  forward/reverse DDNS domains + TSIG keys (adds our catch-all alongside). Changes are logged
  to `/var/log/keaunbound` and announced via syslog.

## Notes / open items for the test environment

- Confirm `PLUGIN_DEPENDS` python version matches the OPNsense base (Makefile
  currently `py311-dnspython`; tkreagan used py313 — adjust to the box).
- Verify the rc.d/kea precmd-before-daemon ordering (Phase 4).
- The old v3.8 files (`build_plugin.sh`, `healthcheck.sh`, `test_hook.sh`) remain
  on `main` and are left in the tree for now; they will be retired once this line
  is proven.
