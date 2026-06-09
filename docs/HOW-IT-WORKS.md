# How it works

`os-kea-unbound` (DDNS edition) bridges Kea DHCP leases into Unbound DNS over two
paths, without patching any OPNsense core files.

```
 kea-dhcp4/6 ─── leases ───► kea-dhcp-ddns (D2) ── RFC 2136 (TSIG) ──► kea-unbound-ddns
      │                                                                  (127.0.0.1:53535)
      │ existing leases (control socket)                                       │
      └──────────────────────────► lease-sync ─────────────────────────► unbound-control
                                                                                │
                                                          /usr/local/etc/unbound.opnsense.d/
                                                                  keaunbound.conf
                                                            (persists across restarts)
```

- **Real-time path** — Kea's built-in `kea-dhcp-ddns` (D2) sends TSIG-signed RFC 2136
  updates to a loopback listener, which writes them to Unbound the instant a lease is
  granted, renewed, or released.
- **Initial / seed path** — existing leases (read from the Kea control socket) are
  seeded on enable/start, so nothing waits for a renewal.
- **Persistence** — every record is mirrored into
  `/usr/local/etc/unbound.opnsense.d/keaunbound.conf`, which OPNsense's generated
  `unbound.conf` always `include:`s — so records survive Unbound restarts and reboots
  with no repopulation, as long as the lease is still within its window.

The only persistent Kea setting it changes is *enabling the DDNS daemon*, and only if
you didn't already have it on — recorded and reverted on disable/uninstall. It never
overwrites an existing user DDNS config (it adds a catch-all alongside). All edits are
atomic and logged.

## What it manages (and what it leaves alone)

The plugin registers **dynamic (non-reserved) leases only** — both forward (A/AAAA)
and reverse (PTR) — and is careful never to touch anything OPNsense already manages:

- **Dynamic leases** → registered and kept current (added on grant/renew, removed on
  release/expiry, old address dropped when a host moves).
- **DHCP reservations and Host Overrides** → left entirely to OPNsense, which already
  writes them into Unbound's `host_entries.conf`. The listener and the cleanup pass
  both guard these: a DDNS update for a reserved address is skipped, and stale-record
  pruning will never remove a static or reserved record. This division of labour is
  what keeps internal DNS resolving even while dynamic records churn.

## Why it replaces the old (v3.x) plugin

The previous plugin worked by **patching OPNsense's core Kea files** (its models, PHP
and templates) at install time to bolt DDNS onto the GUI. That approach was fragile in
ways this rewrite eliminates:

| | Old v3.x (core-file patching) | This 0.x (native DDNS) |
|---|---|---|
| **OPNsense upgrades** | A core update overwrites the patched files and silently breaks DDNS — or worse, leaves damaged files behind (a production box was found with several such files, which broke the unrelated Kea *Options* tab). | Nothing in core is touched, so upgrades can't break it. |
| **Uninstall** | Leaves patched/edited core files behind; never truly clean. | Trivially clean — there is nothing in core to undo. |
| **Per-subnet setup** | Manual DDNS wiring, often per subnet. | Zero setup — DDNS is configured globally and automatically. |
| **DNS update transport** | Bespoke. | Kea's *own* `kea-dhcp-ddns` (D2) over standard RFC 2136 + TSIG. |
| **Static entries** | Easy to clobber. | Reservations and Host Overrides are never touched. |
| **Security** | — | TSIG on by default; the listener rejects unsigned and wrong-key updates. |

Same outcome (dynamic leases resolve in Unbound, forward and reverse), but built on
Kea's supported DDNS plumbing instead of monkey-patching the firewall.

## The Unbound "manual overwrites" notice

After enabling, the Unbound settings page shows: *"The configuration contains manual
overwrites, these may interfere with the settings configured here."* This is
**expected and benign.** The plugin persists its records in
`/usr/local/etc/unbound.opnsense.d/keaunbound.conf` — OPNsense's documented
custom-include source dir, which is the only way records survive an Unbound restart.
OPNsense flags any custom include there with that generic notice. Our file only *adds*
`local-data:` records; it does not change any Unbound setting, so nothing actually
interferes. The notice clears if you disable/uninstall the plugin.

## Housekeeping

- A daily task (`/etc/periodic/daily/500.keaunbound-clean`) prunes stale records; it
  has an anomaly guard so a transient/empty Kea response can never trigger a mass
  deletion.
- Logs: `/var/log/keaunbound/keaunbound.log` (rotated by newsyslog, 1 MB × 10).

## Build from source

Build from the OPNsense plugins tree on an OPNsense/FreeBSD host:

```sh
git clone https://github.com/opnsense/plugins /usr/plugins
git clone https://github.com/JameZUK/os-kea-unbound /usr/plugins/dns/kea-unbound
cd /usr/plugins/dns/kea-unbound
make package          # -> work/pkg/os-kea-unbound-<version>.pkg
pkg add work/pkg/os-kea-unbound-*.pkg
```
