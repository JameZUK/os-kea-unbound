# os-kea-unbound (DDNS edition, 0.x)

**OPNsense plugin: register Kea DHCP leases in Unbound DNS — automatically, with no core-file patching.**

> This is the rewritten `0.x` line. It replaces the v3.x approach (which patched
> Kea's MVC/PHP files at install time) with a clean standalone plugin that uses
> Kea's *native* Dynamic DNS. See `PLAN.md` for the full design and history.

When a DHCP client gets a lease, its hostname resolves in Unbound within moments —
forward (A/AAAA) and reverse (PTR) — and stays resolvable across Unbound restarts.

## How it works

```
 kea-dhcp4/6 ─── leases ───► kea-dhcp-ddns (D2) ── RFC 2136 (TSIG) ──► kea-unbound-ddns
      │                                                                  (127.0.0.1:53535)
      │ reservations + existing leases (control socket)                        │
      └──────────────────────────► lease-sync ─────────────────────────► unbound-control
                                                                                │
                                                          /var/unbound/etc/keaunbound.conf
                                                            (persists across restarts)
```

- **Real-time path:** Kea's built-in `kea-dhcp-ddns` (D2) sends TSIG-signed RFC 2136
  updates to a loopback listener, which writes them to Unbound.
- **Static/initial path:** existing leases (Kea control socket) and reservations
  (Kea config) are seeded on enable/start so nothing waits for a renewal.
- **Persistence:** every record is mirrored into `/var/unbound/etc/keaunbound.conf`,
  which OPNsense's generated `unbound.conf` always `include:`s — so records survive
  Unbound restarts with no repopulation.

## What makes it different

- **No core-file patching.** Nothing edits Kea's models/PHP/templates, so OPNsense
  upgrades can't break it and uninstall is trivially clean.
- **Zero per-subnet setup.** DDNS is configured *globally and automatically* — you
  don't touch each subnet (the usual Kea-DDNS chore).
- **Auto-provisioned TSIG.** An HMAC-SHA256 key is generated once and wired into both
  Kea D2 and the listener; on by default.
- **Config-safe.** The only persistent Kea setting it changes is enabling the DDNS
  daemon, and only if you didn't already have it on — recorded and reverted on
  disable/uninstall. It never overwrites an existing user DDNS config (it adds a
  catch-all alongside). All edits are atomic; changes are logged + announced.

## Requirements

- OPNsense 26.1+ (Kea is the DHCP server; ISC dhcpd is gone)
- Kea DHCPv4 and/or DHCPv6 enabled, Unbound the active resolver
- `py313-dnspython` (declared in `PLUGIN_DEPENDS`, installed by `pkg`)

## Install

Build from the OPNsense plugins tree on an OPNsense/FreeBSD host:

```sh
git clone https://github.com/opnsense/plugins /usr/plugins
git clone https://github.com/JameZUK/os-kea-unbound /usr/plugins/dns/kea-unbound
cd /usr/plugins/dns/kea-unbound
make package          # -> work/pkg/os-kea-unbound-0.x.pkg
pkg add work/pkg/os-kea-unbound-*.pkg
```

## Configuration

**Services → Kea Unbound DDNS → Settings**, tick **Enable**, Save. That's it — the
plugin enables Kea's DDNS daemon, points it at the listener, generates the TSIG key,
and seeds existing leases/reservations. Optional:

| Setting | Default |
|---|---|
| Qualifying suffix | the firewall domain |
| TSIG | on (HMAC-SHA256, auto key) |
| Listener port | 53535 (loopback) |
| Aggressive cleanup | on (drop a host's old address when it moves) |

## Status & maintenance

- **Services → Kea Unbound DDNS → Status:** listener health, record count, TSIG
  state, whether the plugin manages Kea's DDNS, recent activity, and a **Sync now**
  button.
- CLI (configd):
  ```sh
  configctl keaunbound status      # listener state
  configctl keaunbound sync        # re-seed leases + reservations
  configctl keaunbound audit       # report drift vs Kea (read-only, JSON)
  configctl keaunbound clean       # prune stale records Kea no longer knows
  ```
- Logs: `/var/log/keaunbound/keaunbound.log` (rotated by newsyslog).

## Uninstall

Disabling the plugin (Settings → untick Enable → Save) fully reverts everything:
stops the listener, reverts Kea's DDNS daemon if the plugin enabled it, flushes the
plugin's records, and regenerates a clean Kea config. `pkg delete` does the same via
a pre-deinstall safety net. Because nothing in core was patched, there is nothing
else to undo.

## License

BSD-2-Clause.
