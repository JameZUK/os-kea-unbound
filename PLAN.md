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
- **Scope: DYNAMIC leases only.** Kea+Unbound have no native dynamic-lease DNS —
  that is this plugin's sole purpose. OPNsense itself already registers
  reservations and manual Host Overrides (host_entries.conf, forward+reverse), so
  the plugin registers only *non-reserved* leases and never adds/deletes/cleans a
  reserved or statically-owned name. (Each dynamic lease still gets both A/AAAA
  and PTR.) This avoids `unbound-control local_data_remove <name>` — which deletes
  ALL records at a name — ever evicting OPNsense's static records from runtime.
  *(Learned from a prod incident: clean/reconcile touched reservation names, the
  name-wide remove evicted OPNsense's records, and hostname-based firewall aliases
  went NXDOMAIN. clean now skips owned names and aborts on an anomalous
  (partial-control-socket) prune; the daily cron is the hardened reconcile.)*
- **DNS UPDATE prerequisites: intentionally ignored; always reply NOERROR.** The
  zone has a single owner (Kea via D2). Honouring RFC 2136 prerequisites means
  RFC 4703 conflict resolution, which is DHCID-based — and we deliberately do NOT
  write DHCID (it dragged names into local_data_remove and clobbered co-located
  records). Honouring prereqs without DHCID would *break* Kea's update dance
  (its "name in use?" prereq fails against our existing record, the DHCID
  fallback we can't satisfy, so Kea gives up). For a single-owner zone
  last-write-wins is correct; the only thing forgone is arbitration between two
  different clients claiming the same hostname (rare, benign). Also why the
  listener replies BEFORE doing the zone work (nothing to learn from the prereqs).
- **Stale pruning: Kea-driven + a daily reconcile.** Kea sends DDNS removals on
  lease release/decline and reclaims expired leases (which also remove), so
  records drop as leases go away. `etc/periodic/daily/500.keaunbound-clean` runs
  `configctl keaunbound clean` once a day as belt-and-braces to catch drift (a
  dropped UDP NCR, an out-of-band change). No-ops when the plugin is disabled.

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

## Thorough test pass (OPNsense 26.1.9 test box)

Every tool/feature exercised on real hardware (see tests/integration/). All green:
- **Listener (real-time DDNS):** A/AAAA/PTR add, dual-stack preserve on single-family
  delete, full delete, aggressive cleanup — 10/10.
- **TSIG security:** unsigned and wrong-key UPDATEs rejected.
- **Static guard:** host_entries.conf entries never overwritten.
- **Service:** daemon(8) respawn after crash.
- **Persistence:** records survive `configctl unbound restart`.
- **kea_sync injector:** globals injected, per-subnet override stripped, D2 catch-all +
  TSIG, idempotent, user DDNS preserved.
- **Static sync:** reservations + leases (control socket).
- **audit/clean:** stale detected + pruned; reachability-guarded.
- **Config safety + teardown:** ownership marker record/revert; full clean revert.
- **Package:** pkg build + clean install + `+PRE_DEINSTALL` teardown on delete.
- **GUI (Playwright):** Settings + Status + Records render with live data; Sync now works.
- **Unit:** 28/28. **Integration:** 10 listener + 27 extra (incl. dual-stack ANY-delete,
  reservation guard, lease lifecycle, multi-RRset, v6→v4 ordering).

Three real bugs found and fixed by this pass:
1. Listener treated every UPDATE as an add (branched on `rdclass`, not dnspython's
   `.deleting`) — deletes never worked.
2. TSIG bypass — unsigned UPDATEs were processed when a key was configured.
3. Persistence — wrote the include to the chroot `/var/unbound/etc/` (wiped on every
   unbound start); must write the source `/usr/local/etc/unbound.opnsense.d/`.

The full client -> Kea NCR -> D2 -> listener path was later proven on a live production
network (see below); synthetic NCR injection isn't viable (Kea's UDP NCR wire format is
not raw JSON), so a real client was the only way to exercise it.

## Production migration & live-client findings

Migrated a live prod firewall from the v3.8 patch-based edition to 0.x (clean uninstall
reverted the core patches; staged install + enable). The real client traffic exercised
paths the isolated test box could not, and surfaced four issues — all fixed, regression-
tested (v4 + v6), and verified live:

1. **No NCRs at all.** The injector set `ddns-send-updates: true` but never wrote the
   `dhcp-ddns` block, so Kea's master switch `dhcp-ddns.enable-updates` stayed false
   (Kea logged "DDNS: disabled"). Now inject `dhcp-ddns {enable-updates, server-ip,
   server-port}` pointed at D2 (127.0.0.1:53001) + `ddns-update-on-renew: true`.
2. **Forward catch-all `.` does not work in Kea D2** (it matches by DNS suffix →
   `DHCP_DDNS_NO_MATCH`). Register the qualifying-suffix zone explicitly; `.` kept only as
   a harmless fallback. (Reverse `in-addr.arpa.`/`ip6.arpa.` are real suffixes and worked.)
3. **Static records clobbered.** `unbound-control local_data_remove <name>` drops EVERY
   type at a name, so a lease-release ANY-delete on a reverse name wiped a reserved host's
   static PTR (and DHCID writes dragged names into removes). Fix: the ANY branch bails on
   static/reserved names; we no longer write DHCID.
4. **Dual-stack family loss.** A forward FQDN holds A (kea-dhcp4) + AAAA (kea-dhcp6); a
   single-family removal's name-wide cleanup wiped the other family. Fix: never honour a
   name-wide ANY-delete on a *forward* name (the specific A/AAAA delete handles real
   removal); reverse names (one PTR) still honour it.

**Reservation-aware guard:** OPNsense rewrites `host_entries.conf` on its own cadence, so
during a regen window a reservation isn't recognised as static. The guard now also loads
Kea reservations from the generated dhcp4/6 configs and protects any record on a reserved
IP from deletion (forward by rdata, reverse by the IP's PTR name) — a reservation is a
permanent host<->IP mapping.

## Test parity with v3.8 (`test_hook.sh`)

The old suite (29 shell tests) targeted the run_script hook driven by Kea env-vars; the
new suite (28 unit + 37 integration) targets native DDNS + the listener. Core behaviours
migrated (v4/v6 lifecycle, dual-stack preserve, static guard incl. independent fwd/PTR
#11, aggressive cleanup, idempotency #10), and the new suite adds TSIG enforcement,
persistence, daemon respawn, static-PTR ANY-delete survival, family-safe ANY-delete, and
the reservation guard. Two old areas are **intentionally not migrated** because the
mechanism/feature changed, not as gaps:

- **Per-Kea-hook-event parsing** (old `lease*_renew/_expire/_decline/_rebind`,
  `committed`-with-`DELETED_LEASES`, unknown/empty hook): the run_script hook is gone;
  Kea emits NCRs now. The behavioural equivalent (add on add-NCR, remove on delete-NCR)
  is covered by A4/A5 + A15.
- **Per-subnet / per-reservation DNS *domain*** (old #7): replaced by a single global
  qualifying suffix (a locked decision above) — multi-domain-per-subnet is not supported.
- **MAC-address fallback naming** (`device-<mac>`, old #6): Kea now generates names for
  nameless clients (`host-<hex>` via ddns-replace-client-name / ddns-generated-prefix).

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
