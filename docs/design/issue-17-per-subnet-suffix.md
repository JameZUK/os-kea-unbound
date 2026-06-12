# Design: per-subnet DNS suffix (issue #17)

**Status:** proposed
**Issue:** [#17 — all leases get the dns suffix of the firewall](https://github.com/JameZUK/os-kea-unbound/issues/17)

## Problem

A site running multiple VLANs, each with its own domain (e.g. `iot.example.`,
`lan.example.`, `guest.example.`), wants a dynamic lease to be registered under
**its subnet's** domain. Today every lease is registered under a single,
firewall-wide suffix, so per-VLAN DNS is broken.

## Root cause

`kea-config-sync.py` writes one **global** qualifying suffix at the `Dhcp4`/`Dhcp6`
root of the generated Kea config, which every subnet inherits:

```python
# load_settings()
suffix = _text(gen, "qualifying_suffix") or _text(root.find("./system"), "domain", "")
# patch_dhcp()
node["ddns-qualifying-suffix"] = s["suffix"]   # root scope → all subnets
```

Kea then qualifies every client name with that one suffix before sending the NCR,
so the listener only ever sees `<host>.<firewall-domain>`.

## Where the per-subnet domain is configured

Both candidate sources already exist per subnet in OPNsense, in the **same subnet
editor**: *Services → Kea DHCP → KEA DHCPv4 (or DHCPv6) → Subnets → edit a subnet*.
They surface in the generated Kea config and in `config.xml` under
`OPNsense/Kea/dhcp{4,6}/subnets/subnet{4,6}`:

1. **DHCP "Domain name" option** — `option_data/domain_name` (option 15); appears in
   the generated config as a per-subnet `option-data` entry
   `{"name": "domain-name", "data": "<domain>"}`. This is the domain the VLAN's
   clients receive.

   ⚠️ **Gotcha that explains the symptom:** subnets default to **"Automatically
   collect option data"** (`option_data_autocollect = 1`). With it on, OPNsense
   auto-fills `domain-name` with the *firewall's* system domain. So to give a VLAN
   its own domain the admin must untick auto-collect and set "Domain name"
   explicitly. (Confirmed on the test box: dhcp4 subnet had `autocollect=1` and the
   generated config carried `domain-name=internal`, the firewall domain.)

2. **Native per-subnet DDNS "Qualifying suffix"** — `ddns_qualifying_suffix`; the
   most direct expression of "what suffix DDNS should use for this subnet". It lives
   under core OPNsense's native-DDNS UI (next to `ddns_forward_zone`), which this
   plugin otherwise bypasses, so a user of this plugin may never have touched it.

## Resolution rule (implemented)

Per subnet, choose the suffix in this order (first non-empty wins):

1. the subnet's `domain-name` option, else
2. the current **global** suffix (plugin setting → firewall domain).

The `domain-name` option is the clean choice because it is already present in the
**generated** Kea config (a single source both code paths read) and is exactly what
defines a VLAN's domain for its clients. Untouched subnets keep today's behaviour.

The native per-subnet **DDNS "Qualifying suffix"** (`ddns_qualifying_suffix`) is a
deliberate **future enhancement** (see open questions): honouring it would require
correlating `config.xml` subnets to generated subnet-ids by CIDR, since core does
not emit that field into the generated DHCP config. It is rarely set by users of
this plugin (they bypass native DDNS), so v1 uses `domain-name` only.

## Changes

### 1. Shared helper — `lib/suffix.py` (new, pure)

A dependency-free module both code paths import, so the resolution rule lives in one
place. Reads the **generated** Kea config (single source of truth, already
post-`option_data_autocollect`):

- `subnet_suffix(subnet, global_suffix)` — domain-name option, else global fallback.
- `iter_subnets(root, subnet_key)` — subnets incl. `shared-networks` (mirrors
  `reservations()`).
- `suffix_by_subnet_id(root, subnet_key, global_suffix)` — `{subnet_id: suffix}`;
  subnet-id is what both the control socket and memfile CSV report per lease.
- `norm()` / `clean()` — comparison form (lowercase, no dots) and storage form.

### 2. `kea-config-sync.py` → `patch_dhcp()`

For each subnet (incl. shared-network subnets), set its own
`ddns-qualifying-suffix` from the resolution rule **only when it differs from the
global**; keep writing the global at root as the fallback. Kea honours subnet scope
over global, so untouched subnets are unaffected.

### 3. `kea-config-sync.py` → `patch_d2()` — the important bit

D2 matches **forward** zones by DNS suffix, and the `.` catch-all does **not** match
a normal FQDN (confirmed on Kea 3.0.3 — `DHCP_DDNS_NO_MATCH`; see
[[kea-native-ddns-facts]]). Today we register only the global suffix zone (+ a
harmless `.`). With multiple suffixes we must register **a forward-ddns domain per
distinct suffix**, each pointing at our listener (`127.0.0.1:<port>`) with our TSIG
key:

```python
# main() collects the distinct suffixes once (global + every subnet domain-name
# across both families) into s["suffixes"]; patch_d2 turns each into a zone:
our_fwd = [catchall(norm(sfx) + ".") for sfx in s["suffixes"]] + [catchall(".")]
```

Reverse (`in-addr.arpa.`/`ip6.arpa.`) and TSIG are unchanged — reverse already
matches by address and the key is shared. User-defined forward/reverse domains are
still preserved exactly as today.

### 4. `lib/kea_source.py` → `leases()` / `desired_records()`

`desired_records()` qualifies bare lease hostnames with a single suffix to seed
existing leases. Under per-subnet suffixes it must use **each lease's** suffix or it
will seed a forward record under the wrong name **and** duplicate the live path's
record. So:

- `leases(family)` (and `_family_leases`) start returning `(hostname, ip, subnet_id)`
  — subnet-id is present on both the control-socket lease and the CSV (`subnet_id`
  column).
- `desired_records()` builds the `subnet_suffix_map` once per family and calls
  `host_fqdn(host, suffix_for[subnet_id])` per lease (fallback to global on an
  unknown id). Already-qualified multi-label hostnames are still used verbatim by
  `host_fqdn`, matching the live path.

### 5. `lease-sync.py`

No structural change — it consumes `desired_records()`, which now qualifies
correctly per subnet. (It passes `settings["suffix"]` today; that becomes the global
fallback that `desired_records` uses internally.)

### 6. No change needed

- **`clean.py`** — prunes by **address**, not name (deliberately: see
  `is_stale_record`), so mixed suffixes can't cause false prunes. ✅
- **The listener (`kea-unbound-ddns.py`)** — registers whatever FQDN Kea sends; it
  never applies a suffix. ✅
- **`start.py`** — already resolves the suffix only for logging; unaffected. ✅

## Edge cases

- **Subnet with no domain / auto-collect on** → falls back to the global suffix
  (today's behaviour). No regression for single-domain sites.
- **Shared networks** — walk `shared-networks[].subnet{4,6}` everywhere subnets are
  enumerated (mirror `reservations()`).
- **IPv6** — identical handling; v6 subnets often have no `domain-name` option, so
  they lean on `ddns_qualifying_suffix` or the global fallback.
- **Already-qualified hostnames** (client sent an FQDN) — unchanged; `host_fqdn`
  uses them verbatim, so no double-suffixing.
- **Suffix with/without trailing dot, case** — normalise once in the helper.

## Testing

Unit (off-box, no Kea):
- `subnet_suffix_map`: precedence (ddns suffix > domain-name > global), shared
  networks, missing fields, trailing-dot/case normalisation.
- `patch_dhcp`: per-subnet `ddns-qualifying-suffix` set only when it differs from
  global; global still written; idempotent (no rewrite when unchanged).
- `patch_d2`: one forward zone per distinct suffix, all pointing at the listener
  with the key; user domains preserved; idempotent.
- `desired_records`: a two-subnet fixture with different domains qualifies each
  lease correctly; unknown subnet-id falls back to global.

Live (test box 192.168.0.216): add a second subnet with its own domain (untick
auto-collect, set "Domain name"), take a lease on each VLAN, confirm each resolves
under its own suffix forward + reverse, and that `clean` prunes nothing spurious.

## Backward compatibility

Single-domain sites are unaffected: with one suffix, the map collapses to the global
value, `patch_dhcp` writes no per-subnet overrides, and `patch_d2` registers exactly
the same one suffix zone as today. The feature is automatic (driven by existing
per-subnet config) — no new plugin setting required, though a "honour per-subnet
domains" toggle could be added later if an opt-out is wanted.

## Open questions

1. Should we also honour the native per-subnet DDNS **"Qualifying suffix"**
   (`ddns_qualifying_suffix`)? Doing so means reading `config.xml` and joining its
   subnets to generated subnet-ids by CIDR. (Proposed: add later if requested; if
   both it and `domain-name` are set, `ddns_qualifying_suffix` would win as the more
   DDNS-specific intent.)
2. Should a per-subnet domain also drive the **reverse** zone delegation, or is the
   shared `in-addr.arpa.`/`ip6.arpa.` catch-all (matched by address) sufficient?
   (Proposed: catch-all is sufficient; PTRs don't depend on the forward suffix.)
