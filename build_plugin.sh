#!/bin/sh

# 1. Define Variables
PLUGIN_NAME="os-kea-unbound"
VERSION="3.8.0"
BUILD_DIR="./${PLUGIN_NAME}_build"
STAGE_DIR="${BUILD_DIR}/stage"

echo ">>> Cleaning up old build directory..."
rm -rf "${BUILD_DIR}"
mkdir -p "${STAGE_DIR}"

# Mandated directories
KEA_SCRIPT_DIR="${STAGE_DIR}/usr/local/share/kea/scripts"
UPDATE_HOOK_DIR="${STAGE_DIR}/usr/local/etc/rc.syshook.d/update"
BOOT_HOOK_DIR="${STAGE_DIR}/usr/local/etc/rc.syshook.d/early"
START_HOOK_DIR="${STAGE_DIR}/usr/local/etc/rc.syshook.d/start"
LOG_ROT_DIR="${STAGE_DIR}/usr/local/etc/newsyslog.conf.d"
BIN_DIR="${STAGE_DIR}/usr/local/bin"

echo ">>> Creating directory structure..."
mkdir -p "${KEA_SCRIPT_DIR}" "${UPDATE_HOOK_DIR}" "${BOOT_HOOK_DIR}" "${START_HOOK_DIR}" "${LOG_ROT_DIR}" "${BIN_DIR}"
mkdir -p "${STAGE_DIR}/usr/local/etc/inc/plugins.inc.d"

echo ">>> Generating Plugin Files..."

# --- 1. The DNS Hook Script ---
cat << 'EOF' > "${KEA_SCRIPT_DIR}/kea-unbound-hook.sh"
#!/bin/sh
# Paths are env-overridable so the regression test suite can point them at fixtures.
LOG_FILE="${LOG_FILE:-/var/log/kea-unbound.log}"
UNBOUND_CONF="${UNBOUND_CONF:-/var/unbound/unbound.conf}"
HOST_ENTRIES="${HOST_ENTRIES:-/var/unbound/host_entries.conf}"
KEA_DHCP4_CONF="${KEA_DHCP4_CONF:-/usr/local/etc/kea/kea-dhcp4.conf}"
KEA_DHCP6_CONF="${KEA_DHCP6_CONF:-/usr/local/etc/kea/kea-dhcp6.conf}"
# Serialize concurrent executions to prevent dual-stack race conditions
if [ -z "$_KEA_UNBOUND_LOCKED" ]; then
    export _KEA_UNBOUND_LOCKED=1
    exec lockf -k -t 10 /tmp/kea-unbound.lock "$0" "$@"
fi
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" >> "$LOG_FILE"; }
uc() {
    local OUT RC
    OUT=$(unbound-control -c "$UNBOUND_CONF" "$@" 2>&1)
    RC=$?
    [ $RC -ne 0 ] && log error "unbound-control $* failed (rc=$RC): $OUT"
    return $RC
}
normalize_hostname() { echo "$1" | tr 'A-Z' 'a-z' | sed 's/\..*//' | sed 's/[^a-z0-9-]//g'; }
# Issue #7: per-subnet/per-reservation domain lookup against Kea config.
# Fall through to hostname -d / home.arpa if no match.
# Args: IP, IP_VER (4|6), IDENT (hw-address for v4, duid for v6; may be empty).
get_domain() {
    local IP="$1" VER="$2" IDENT="$3" D CONF
    if [ "$VER" = "6" ]; then CONF="$KEA_DHCP6_CONF"; else CONF="$KEA_DHCP4_CONF"; fi
    if [ -f "$CONF" ]; then
        D=$(/usr/local/bin/python3 - "$IP" "$VER" "$IDENT" "$CONF" <<'PYEOF' 2>/dev/null
import json, sys, ipaddress, os
ip, ver, ident, conf = sys.argv[1], sys.argv[2], sys.argv[3].lower(), sys.argv[4]
try:
    cfg = json.load(open(conf))
except Exception:
    sys.exit(1)
root = cfg.get("Dhcp4") or cfg.get("Dhcp6") or {}
subkey = "subnet4" if ver == "4" else "subnet6"
subs = [s for n in root.get("shared-networks", []) or [] for s in n.get(subkey, []) or []]
subs += root.get(subkey, []) or []
def domain_of(node):
    for o in node.get("option-data", []) or []:
        if o.get("name") == "domain-name" and o.get("data"):
            return o["data"]
    return None
# 1) reservations (most specific). Match by IP or by hw-address/DUID.
for s in subs:
    for r in s.get("reservations", []) or []:
        ips = []
        if ver == "4":
            if r.get("ip-address"): ips.append(r["ip-address"])
        else:
            ips += list(r.get("ip-addresses") or [])
            if r.get("ip-address"): ips.append(r["ip-address"])
        matched = ip in ips
        if not matched and ident:
            hw = (r.get("hw-address") or "").lower()
            duid = (r.get("duid") or "").lower()
            if ident == hw or ident == duid:
                matched = True
        if matched:
            d = domain_of(r)
            if d:
                print(d); sys.exit(0)
# 2) subnet CIDR match.
try:
    target = ipaddress.ip_address(ip)
except ValueError:
    sys.exit(1)
for s in subs:
    net = s.get("subnet")
    if not net: continue
    try:
        if target in ipaddress.ip_network(net, strict=False):
            d = domain_of(s)
            if d:
                print(d); sys.exit(0)
    except ValueError:
        continue
sys.exit(1)
PYEOF
)
    fi
    if [ -n "$D" ]; then
        echo "$D"
        return
    fi
    D=$(hostname -d 2>/dev/null)
    [ -z "$D" ] && echo "home.arpa" || echo "$D"
}
reverse_ipv4() { echo "$1" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}'; }
reverse_ipv6() {
    local result
    result=$(/usr/local/bin/python3 -c "import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]).reverse_pointer)" "$1" 2>/dev/null)
    if [ -z "$result" ]; then
        log error "Failed to compute IPv6 reverse pointer for $1"
        return 1
    fi
    echo "$result"
}
get_ptr_name() { [ "$1" = "4" ] && reverse_ipv4 "$2" || reverse_ipv6 "$2"; }
# Issue #6: short-circuit on records owned by Unbound's host_entries.conf
# (Register DHCP Static Mappings). Skip both add and remove — skipping only
# remove still leaves a brief NXDOMAIN window on the add path.
is_static_forward() {
    local FQDN="$1" TYPE="$2"
    [ -f "$HOST_ENTRIES" ] || return 1
    grep -Eq "^local-data:[[:space:]]+\"${FQDN}\.?[[:space:]]+([0-9]+[[:space:]]+)?IN[[:space:]]+${TYPE}[[:space:]]" "$HOST_ENTRIES"
}
is_static_ptr() {
    local IP="$1"
    [ -f "$HOST_ENTRIES" ] || return 1
    grep -Eq "^local-data-ptr:[[:space:]]+\"${IP}[[:space:]]" "$HOST_ENTRIES"
}
update_dns_entry() {
    local ACTION="$1" IP="$2" HOST="$3" IP_VER="$4" IDENT="$5"
    [ -z "$IP" ] && return
    HOST=$(normalize_hostname "$HOST"); [ -z "$HOST" ] && return
    local FQDN="$HOST.$(get_domain "$IP" "$IP_VER" "$IDENT")"
    local THIS_TYPE="A"; local OTHER_TYPE="AAAA"; local OTHER_VER="6"
    [ "$IP_VER" = "6" ] && THIS_TYPE="AAAA" && OTHER_TYPE="A" && OTHER_VER="4"
    # Issue #10: Kea fires both leases*_committed AND lease*_renew/rebind for
    # the same renewal. Without this guard the same "Added" line is logged twice.
    local CURRENT_IP=$(drill -Q -t $THIS_TYPE "$FQDN" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | awk '{print $NF}' | head -n 1)
    [ "$ACTION" = "add" ] && [ "$CURRENT_IP" = "$IP" ] && return
    # Issue #11: forward and PTR guards are independent. A static PTR for $IP
    # must not suppress an unrelated forward record at $FQDN, and a static
    # forward at $FQDN must not suppress an unrelated PTR.
    local SKIP_FWD=0 SKIP_PTR=0
    is_static_forward "$FQDN" "$THIS_TYPE" && SKIP_FWD=1
    is_static_ptr "$IP" && SKIP_PTR=1
    if [ "$SKIP_FWD" -eq 1 ] && [ "$SKIP_PTR" -eq 1 ]; then
        log info "Skipped $ACTION for $FQDN ($IP) — static forward and PTR"
        return
    fi
    local PRESERVED_IP=$(drill -Q -t $OTHER_TYPE "$FQDN" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | awk '{print $NF}' | head -n 1)
    local PTR_NAME=$(get_ptr_name "$IP_VER" "$IP")
    # Forward record (gated by SKIP_FWD)
    if [ "$SKIP_FWD" -eq 0 ]; then
        uc local_data_remove "$FQDN"
        [ "$ACTION" = "add" ] && uc local_data "$FQDN IN $THIS_TYPE $IP"
    fi
    # PTR record (independently gated by SKIP_PTR)
    if [ "$SKIP_PTR" -eq 0 ] && [ -n "$PTR_NAME" ]; then
        uc local_data_remove "$PTR_NAME"
        [ "$ACTION" = "add" ] && uc local_data "$PTR_NAME PTR $FQDN"
    fi
    local NOTE=""
    [ "$SKIP_FWD" -eq 1 ] && NOTE="$NOTE (forward static)"
    [ "$SKIP_PTR" -eq 1 ] && NOTE="$NOTE (PTR static)"
    if [ "$ACTION" = "add" ]; then
        log info "Added $THIS_TYPE for $FQDN ($IP) [PTR: ${PTR_NAME:-FAILED}]$NOTE"
    else
        log info "Removed $THIS_TYPE for $FQDN ($IP) [PTR: ${PTR_NAME:-FAILED}]$NOTE"
    fi
    # Restore the other-family record drill saw. local_data_remove above wipes
    # ALL types for FQDN — including static records loaded from host_entries.conf,
    # which Unbound only consults at startup. Only meaningful when we touched
    # the forward record.
    if [ -n "$PRESERVED_IP" ] && [ "$SKIP_FWD" -eq 0 ]; then
        local PRES_PTR=$(get_ptr_name "$OTHER_VER" "$PRESERVED_IP")
        uc local_data "$FQDN IN $OTHER_TYPE $PRESERVED_IP"
        [ -n "$PRES_PTR" ] && uc local_data "$PRES_PTR PTR $FQDN"
    fi
}
# leases4_committed / leases6_committed pass indexed env vars (LEASES4_AT<i>_*);
# single-lease callouts (renew/release/expire/decline, v6 rebind) pass singular LEASE4_*/LEASE6_*.
host_or_mac_fallback() { if [ -n "$1" ]; then echo "$1"; else echo "device-$(echo "$2" | tr ':' '-')"; fi; }
case "$1" in
    leases4_committed)
        # Process deletions FIRST so that when the same hostname appears in
        # both sets (IP reassignment), the final ADD wins.
        i=0; SIZE="${DELETED_LEASES4_SIZE:-0}"
        while [ "$i" -lt "$SIZE" ]; do
            ADDR=$(eval "echo \$DELETED_LEASES4_AT${i}_ADDRESS")
            HN=$(eval "echo \$DELETED_LEASES4_AT${i}_HOSTNAME")
            HW=$(eval "echo \$DELETED_LEASES4_AT${i}_HWADDR")
            update_dns_entry "remove" "$ADDR" "$(host_or_mac_fallback "$HN" "$HW")" "4" "$HW"
            i=$((i + 1))
        done
        i=0; SIZE="${LEASES4_SIZE:-0}"
        while [ "$i" -lt "$SIZE" ]; do
            ADDR=$(eval "echo \$LEASES4_AT${i}_ADDRESS")
            HN=$(eval "echo \$LEASES4_AT${i}_HOSTNAME")
            HW=$(eval "echo \$LEASES4_AT${i}_HWADDR")
            update_dns_entry "add" "$ADDR" "$(host_or_mac_fallback "$HN" "$HW")" "4" "$HW"
            i=$((i + 1))
        done
        ;;
    lease4_renew)
        [ -n "$LEASE4_ADDRESS" ] && update_dns_entry "add" "$LEASE4_ADDRESS" "$(host_or_mac_fallback "$LEASE4_HOSTNAME" "$LEASE4_HWADDR")" "4" "$LEASE4_HWADDR"
        ;;
    lease4_release|lease4_expire|lease4_decline)
        [ -n "$LEASE4_ADDRESS" ] && update_dns_entry "remove" "$LEASE4_ADDRESS" "$(host_or_mac_fallback "$LEASE4_HOSTNAME" "$LEASE4_HWADDR")" "4" "$LEASE4_HWADDR"
        ;;
    leases6_committed)
        i=0; SIZE="${DELETED_LEASES6_SIZE:-0}"
        while [ "$i" -lt "$SIZE" ]; do
            ADDR=$(eval "echo \$DELETED_LEASES6_AT${i}_ADDRESS")
            HN=$(eval "echo \$DELETED_LEASES6_AT${i}_HOSTNAME")
            DUID=$(eval "echo \$DELETED_LEASES6_AT${i}_DUID")
            update_dns_entry "remove" "$ADDR" "$(host_or_mac_fallback "$HN" "$DUID")" "6" "$DUID"
            i=$((i + 1))
        done
        i=0; SIZE="${LEASES6_SIZE:-0}"
        while [ "$i" -lt "$SIZE" ]; do
            ADDR=$(eval "echo \$LEASES6_AT${i}_ADDRESS")
            HN=$(eval "echo \$LEASES6_AT${i}_HOSTNAME")
            DUID=$(eval "echo \$LEASES6_AT${i}_DUID")
            update_dns_entry "add" "$ADDR" "$(host_or_mac_fallback "$HN" "$DUID")" "6" "$DUID"
            i=$((i + 1))
        done
        ;;
    lease6_renew|lease6_rebind)
        [ -n "$LEASE6_ADDRESS" ] && update_dns_entry "add" "$LEASE6_ADDRESS" "$(host_or_mac_fallback "$LEASE6_HOSTNAME" "$LEASE6_DUID")" "6" "$LEASE6_DUID"
        ;;
    lease6_release|lease6_expire|lease6_decline)
        [ -n "$LEASE6_ADDRESS" ] && update_dns_entry "remove" "$LEASE6_ADDRESS" "$(host_or_mac_fallback "$LEASE6_HOSTNAME" "$LEASE6_DUID")" "6" "$LEASE6_DUID"
        ;;
esac
EOF
chmod 755 "${KEA_SCRIPT_DIR}/kea-unbound-hook.sh"

# --- 1b. Boot Replay (Issue #13) ---
# After a reboot Unbound starts empty; the hook script only refills entries
# as new lease events fire. This start-hook reads Kea's lease database and
# replays active leases through the hook so dynamic DNS is restored without
# waiting for each client to renew.
cat << 'EOF' > "${START_HOOK_DIR}/50-keaunbound-replay"
#!/bin/sh
HOOK="/usr/local/share/kea/scripts/kea-unbound-hook.sh"
LOG="/var/log/kea-unbound.log"
LEASES4="/var/db/kea/kea-leases4.csv"
LEASES6="/var/db/kea/kea-leases6.csv"
UNBOUND_CONF="/var/unbound/unbound.conf"
KEA4_CONF="/usr/local/etc/kea/kea-dhcp4.conf"
KEA6_CONF="/usr/local/etc/kea/kea-dhcp6.conf"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" >> "$LOG"; }
[ -x "$HOOK" ] || exit 0
# Honour the per-family "Register Leases in Unbound" toggle. Live registration
# only happens when Kea has our hook in its hooks-libraries; replay must obey
# the same gate, per family, or a disabled plugin would silently re-inject all
# leases at every boot. Blank the lease path for any family that's switched off.
grep -q "kea-unbound-hook.sh" "$KEA4_CONF" 2>/dev/null || LEASES4=""
grep -q "kea-unbound-hook.sh" "$KEA6_CONF" 2>/dev/null || LEASES6=""
if [ -z "$LEASES4" ] && [ -z "$LEASES6" ]; then
    log info "Boot replay skipped (registration disabled in Kea config)"
    exit 0
fi
# Wait up to 90s for unbound-control to answer — Unbound takes a moment to
# come up after boot, and we'd silently fail otherwise.
i=0
while [ $i -lt 90 ]; do
    unbound-control -c "$UNBOUND_CONF" status >/dev/null 2>&1 && break
    sleep 1
    i=$((i + 1))
done
if [ $i -ge 90 ]; then
    log error "Boot replay: unbound-control unreachable after 90s, skipping"
    exit 0
fi
log info "Boot replay starting"
# Parse the Kea memfile CSV, filter to active non-expired leases, and replay
# each family through one synthetic leases*_committed event. Every CSV
# column from the lease is mapped into the matching LEASES{4,6}_AT<i>_*
# env var (per Kea run_script schema), so the synthetic event is
# indistinguishable from one Kea would have fired: hostname, hardware
# identifier, valid/preferred lifetimes, CLTT (derived from expire -
# valid_lifetime), subnet id, FQDN forward/reverse flags, lease type,
# IAID, prefix length, etc. are all preserved.
COUNT=$(/usr/local/bin/python3 - "$LEASES4" "$LEASES6" "$HOOK" <<'PYEOF'
import csv, os, subprocess, sys, time
v4_path, v6_path, hook = sys.argv[1], sys.argv[2], sys.argv[3]
now = int(time.time())
# Map Kea memfile CSV column names to the env var suffix used by the
# run_script hook library. Anything in the CSV that has no documented
# env var is still exported under its uppercased column name so future
# hook logic can reach it.
V4_MAP = {
    "address": "ADDRESS", "hwaddr": "HWADDR", "client_id": "CLIENT_ID",
    "valid_lifetime": "VALID_LIFETIME", "subnet_id": "SUBNET_ID",
    "fqdn_fwd": "FQDN_FWD", "fqdn_rev": "FQDN_REV",
    "hostname": "HOSTNAME", "state": "STATE",
    "user_context": "USER_CONTEXT", "pool_id": "POOL_ID",
}
V6_MAP = {
    "address": "ADDRESS", "duid": "DUID",
    "valid_lifetime": "VALID_LIFETIME", "subnet_id": "SUBNET_ID",
    "pref_lifetime": "PREFERRED_LIFETIME", "lease_type": "TYPE",
    "iaid": "IAID", "prefix_len": "PREFIX_LEN",
    "fqdn_fwd": "FQDN_FWD", "fqdn_rev": "FQDN_REV",
    "hostname": "HOSTNAME", "hwaddr": "HWADDR", "state": "STATE",
    "user_context": "USER_CONTEXT", "hwtype": "HWTYPE",
    "hwaddr_source": "HWADDR_SOURCE", "pool_id": "POOL_ID",
}
def replay(path, family):
    if not os.path.exists(path):
        return 0
    seen = {}
    try:
        with open(path) as f:
            for row in csv.DictReader(f):
                try:
                    if int(row.get("state", "0") or 0) != 0:
                        continue
                    exp = row.get("expire", "")
                    if exp and int(exp) <= now:
                        continue
                    addr = (row.get("address") or "").strip()
                    if not addr:
                        continue
                    # Memfile is append-only; keep only the newest row per address.
                    seen[addr] = row
                except (ValueError, KeyError):
                    continue
    except Exception:
        return 0
    if not seen:
        return 0
    env = dict(os.environ)
    cmap = V4_MAP if family == "4" else V6_MAP
    prefix = "LEASES4_AT" if family == "4" else "LEASES6_AT"
    for i, (addr, row) in enumerate(seen.items()):
        for col, value in row.items():
            if value is None:
                continue
            value = value.strip() if isinstance(value, str) else str(value)
            suffix = cmap.get(col, col.upper())
            env[f"{prefix}{i}_{suffix}"] = value
        # CLTT (Client Last Transmission Time) isn't a CSV column but Kea
        # passes it to hooks. Reconstruct it from expire - valid_lifetime.
        try:
            cltt = int(row.get("expire", "0")) - int(row.get("valid_lifetime", "0"))
            if cltt > 0:
                env[f"{prefix}{i}_CLTT"] = str(cltt)
        except (TypeError, ValueError):
            pass
        # Identifier env vars Kea exposes for v6 reservations matching.
        if family == "6" and row.get("duid"):
            env[f"{prefix}{i}_DUID"] = row["duid"].strip().lower()
    if family == "4":
        env["LEASES4_SIZE"] = str(len(seen))
        callout = "leases4_committed"
    else:
        env["LEASES6_SIZE"] = str(len(seen))
        callout = "leases6_committed"
    subprocess.run([hook, callout], env=env, check=False)
    return len(seen)
total = replay(v4_path, "4") + replay(v6_path, "6")
print(total)
PYEOF
)
log info "Boot replay complete (${COUNT:-0} leases replayed)"
EOF
chmod 755 "${START_HOOK_DIR}/50-keaunbound-replay"

# --- 1b. The CLI status/query helper ---
# Convenience wrapper so operators never have to remember the
# `-c /var/unbound/unbound.conf` flag. A bare `unbound-control` reads the
# compiled-in default config (control-enable: no on OPNsense) and fails with
# "connection refused" — the #1 source of "my leases aren't registered!"
# false alarms. This always targets the live config the hook itself uses.
cat << 'EOF' > "${BIN_DIR}/keaunbound-status"
#!/bin/sh
# keaunbound-status — query/inspect the os-kea-unbound DNS registrations.
# Wraps unbound-control against the live OPNsense config so you don't have to
# pass -c /var/unbound/unbound.conf every time.
UNBOUND_CONF="/var/unbound/unbound.conf"
LOG_FILE="/var/log/kea-unbound.log"
REPLAY_HOOK="/usr/local/etc/rc.syshook.d/start/50-keaunbound-replay"
uc() { unbound-control -c "$UNBOUND_CONF" "$@"; }

usage() {
    cat <<USAGE
Usage: keaunbound-status [command]

  (no command)   Show record count + recent log lines (default)
  count          Print number of local-data records
  list           List all local-data records
  find <term>    List records matching <term> (host name or IP, case-insensitive)
  status         Show unbound-control status
  log [N]        Tail the last N kea-unbound log lines (default 40)
  replay         Re-run the boot-time lease replay now
  uc <args...>   Pass arbitrary args straight to unbound-control (-c handled)
  help           Show this help

All unbound-control calls target ${UNBOUND_CONF}.
USAGE
}

case "${1:-summary}" in
    summary)
        if ! uc status >/dev/null 2>&1; then
            echo "unbound-control unreachable via ${UNBOUND_CONF}" >&2
            exit 1
        fi
        echo "local-data records: $(uc list_local_data 2>/dev/null | grep -c .)"
        echo "--- recent log (${LOG_FILE}) ---"
        tail -n 10 "$LOG_FILE" 2>/dev/null
        ;;
    count)
        uc list_local_data 2>/dev/null | grep -c .
        ;;
    list)
        uc list_local_data
        ;;
    find)
        [ -n "$2" ] || { echo "usage: keaunbound-status find <term>" >&2; exit 2; }
        uc list_local_data 2>/dev/null | grep -i -- "$2"
        ;;
    status)
        uc status
        ;;
    log)
        tail -n "${2:-40}" "$LOG_FILE"
        ;;
    replay)
        [ -x "$REPLAY_HOOK" ] || { echo "replay hook not found: $REPLAY_HOOK" >&2; exit 1; }
        "$REPLAY_HOOK"
        ;;
    uc)
        shift
        uc "$@"
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        echo "unknown command: $1" >&2
        usage >&2
        exit 2
        ;;
esac
EOF
chmod 755 "${BIN_DIR}/keaunbound-status"

# --- 2. The Python Patcher Logic ---
# Bulletproofing notes:
#  * Atomic writes (temp file + os.replace) so an interrupted patch can never
#    leave an OPNsense MVC file half-written / corrupt.
#  * Every injection is anchored: if the anchor string is missing (e.g. a
#    future OPNsense refactor renamed it) we record a problem instead of
#    silently writing nothing, and print a summary the installer/repair hook
#    surfaces. The boot/update repair hooks retry, so a transient miss heals.
#  * replace(..., 1) so a repeated anchor cannot inject the block twice.
#  * NOTE: keep this body free of single quotes — it is embedded inside a
#    single-quoted shell string and re-used verbatim by the repair hooks.
PATCH_CMD='import os, shutil, tempfile
files = [
    {"ctrl": "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings4.xml", "model": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml", "php": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php", "anchor": "dhcpv4.general.dhcp_socket_type", "prefix": "dhcpv4", "key": "Dhcp4"},
    {"ctrl": "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings6.xml", "model": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.xml", "php": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.php", "anchor": "dhcpv6.general.fwrules", "prefix": "dhcpv6", "key": "Dhcp6"}
]
def write_atomic(path, data):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d)
    try:
        with os.fdopen(fd, "w") as f: f.write(data)
        os.replace(tmp, path)
    except Exception:
        try: os.remove(tmp)
        except Exception: pass
        raise
problems = []
for fset in files:
    if not os.path.exists(fset["ctrl"]):
        continue
    for fpath in [fset["ctrl"], fset["model"], fset["php"]]:
        if os.path.exists(fpath) and not os.path.exists(fpath + ".bak"):
            try: shutil.copy2(fpath, fpath + ".bak")
            except Exception: pass
    try:
        with open(fset["ctrl"]) as f: content = f.read()
        if "registerDynamicLeases" not in content:
            field = "    <field>\n        <id>" + fset["prefix"] + ".general.registerDynamicLeases</id>\n"
            field += "        <label>Register Leases in Unbound (via os-kea-unbound)</label>\n"
            field += "        <type>checkbox</type>\n        <help>Enable DNS registration (Plugin Feature).</help>\n    </field>\n"
            anchor = "<field>\n        <id>" + fset["anchor"]
            if anchor in content:
                write_atomic(fset["ctrl"], content.replace(anchor, field + "    " + anchor, 1))
            else:
                problems.append(fset["prefix"] + ": form anchor not found")
        with open(fset["model"]) as f: content = f.read()
        if "registerDynamicLeases" not in content:
            m_node = "            <registerDynamicLeases type=\"BooleanField\">\n                <default>0</default>\n            </registerDynamicLeases>\n"
            if "</general>" in content:
                write_atomic(fset["model"], content.replace("</general>", m_node + "        </general>", 1))
            else:
                problems.append(fset["prefix"] + ": model general node not found")
        with open(fset["php"]) as f: content = f.read()
        if "kea-unbound-hook.sh" not in content:
            p_code = "        if ((string)$this->general->registerDynamicLeases === \"1\") {\n"
            p_code += "            if (!isset($cnf[\"" + fset["key"] + "\"][\"hooks-libraries\"])) $cnf[\"" + fset["key"] + "\"][\"hooks-libraries\"] = [];\n"
            p_code += "            $cnf[\"" + fset["key"] + "\"][\"hooks-libraries\"][] = [\"library\" => \"/usr/local/lib/kea/hooks/libdhcp_run_script.so\", \"parameters\" => [\"name\" => \"/usr/local/share/kea/scripts/kea-unbound-hook.sh\", \"sync\" => false]];\n"
            p_code += "        }\n"
            if "File::file_put_contents" in content:
                write_atomic(fset["php"], content.replace("File::file_put_contents", p_code + "        File::file_put_contents", 1))
            else:
                problems.append(fset["prefix"] + ": php config anchor not found")
    except Exception as e:
        problems.append(fset["prefix"] + ": " + str(e))
if problems:
    print("kea-unbound: UI patch warnings: " + "; ".join(problems))
else:
    print("kea-unbound: UI patch OK")'

# --- 3. Persistence Hooks & Log Rotation ---
HOOK_CONTENT="#!/bin/sh
# Kea-Unbound repair hook
/usr/local/bin/python3 -c '$PATCH_CMD'
rm -rf /var/cache/opnsense/volt/*
/usr/sbin/service configd restart"

echo "$HOOK_CONTENT" > "${UPDATE_HOOK_DIR}/50-keaunbound-repair"
echo "$HOOK_CONTENT" > "${BOOT_HOOK_DIR}/50-keaunbound-repair"
chmod 755 "${UPDATE_HOOK_DIR}/50-keaunbound-repair" "${BOOT_HOOK_DIR}/50-keaunbound-repair"

cat << EOF > "${LOG_ROT_DIR}/keaunbound.conf"
/var/log/kea-unbound.log                644  7     500  * J
EOF

# --- 4. Registration ---
echo "<?php function keaunbound_configure() { return; }" > "${STAGE_DIR}/usr/local/etc/inc/plugins.inc.d/keaunbound.inc"

# --- 5. Installation Scripts ---
cat << EOF > "${BUILD_DIR}/+POST_INSTALL"
#!/bin/sh
# Bulletproof install: every step is best-effort and independent so a single
# failure never aborts the pkg transaction or leaves a half-installed plugin.
# The UI patch self-heals on the next boot/update via the repair hooks even if
# it cannot be applied right now.
mkdir -p /usr/local/share/kea/scripts 2>/dev/null
chmod 755 /usr/local/share/kea /usr/local/share/kea/scripts 2>/dev/null
chmod 755 /usr/local/bin/keaunbound-status 2>/dev/null
touch /var/log/kea-unbound.log 2>/dev/null
chmod 644 /var/log/kea-unbound.log 2>/dev/null
if [ -x /usr/local/bin/python3 ]; then
    /usr/local/bin/python3 -c '$PATCH_CMD' || echo "kea-unbound: UI patch step failed; the boot/update repair hook will retry."
else
    echo "kea-unbound: python3 not found; UI patch deferred to the repair hook."
fi
rm -rf /var/cache/opnsense/volt/* 2>/dev/null
/usr/sbin/service configd restart >/dev/null 2>&1 || true
echo "Plugin installed. Please go to Services > Kea DHCP > Settings."
EOF

cat << 'EOF' > "${BUILD_DIR}/+PRE_DEINSTALL"
#!/bin/sh
# Bulletproof uninstall: never abort the pkg transaction, and leave the box in
# a clean, working state even after an OPNsense upgrade.
#  Step 1 (issue #9): do NOT restore .bak files (captured at install time; may
#          be stale after an OPNsense upgrade). Strip only the blocks we
#          injected, matched by signature, with atomic writes; discard the .bak.
#  Step 2: scrub our hook out of the *generated* kea-dhcp{4,6}.conf so Kea never
#          references the about-to-be-deleted hook script and fails to start.
#  Step 3: best-effort reload so the change goes live now.
[ -x /usr/local/bin/python3 ] && /usr/local/bin/python3 - <<'PYEOF'
import os, re, json, tempfile
def write_atomic(path, data):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d)
    try:
        with os.fdopen(fd, "w") as f: f.write(data)
        os.replace(tmp, path)
    except Exception:
        try: os.remove(tmp)
        except Exception: pass

# --- Step 1: un-patch the OPNsense MVC templates ---
sets = [
    {"ctrl": "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings4.xml",
     "model": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml",
     "php":   "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php"},
    {"ctrl": "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings6.xml",
     "model": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.xml",
     "php":   "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.php"},
]
ctrl_re  = re.compile(r"[ \t]*<field>\s*<id>[^<]*registerDynamicLeases[^<]*</id>.*?</field>[ \t]*\n", re.DOTALL)
model_re = re.compile(r"[ \t]*<registerDynamicLeases[^>]*>.*?</registerDynamicLeases>[ \t]*\n", re.DOTALL)
# [ \t]* (not the literal 8-space prefix) so the leading indentation injected
# ahead of the block is removed too — a true inverse with no whitespace drift
# across repeated install/uninstall cycles.
php_re   = re.compile(r"[ \t]*if \(\(string\)\$this->general->registerDynamicLeases === \"1\"\) \{.*?\n[ \t]*\}\n", re.DOTALL)
def strip(path, pat):
    if not os.path.exists(path):
        return
    try:
        with open(path, "r") as f:
            c = f.read()
        c2 = pat.sub("", c, count=1)
        if c2 != c:
            write_atomic(path, c2)
    except Exception:
        pass
for s in sets:
    strip(s["ctrl"],  ctrl_re)
    strip(s["model"], model_re)
    strip(s["php"],   php_re)
    for p in (s["ctrl"], s["model"], s["php"]):
        bak = p + ".bak"
        if os.path.exists(bak):
            try: os.remove(bak)
            except Exception: pass

# --- Step 2: scrub our hook from the generated Kea config(s) ---
for conf, root in (("/usr/local/etc/kea/kea-dhcp4.conf", "Dhcp4"),
                   ("/usr/local/etc/kea/kea-dhcp6.conf", "Dhcp6")):
    if not os.path.exists(conf):
        continue
    try:
        with open(conf) as f:
            cfg = json.load(f)
    except Exception:
        continue
    node = cfg.get(root)
    if not isinstance(node, dict):
        continue
    hooks = node.get("hooks-libraries")
    if not isinstance(hooks, list):
        continue
    kept = []
    for h in hooks:
        name = ""
        if isinstance(h, dict) and isinstance(h.get("parameters"), dict):
            name = str(h["parameters"].get("name", ""))
        if "kea-unbound-hook.sh" in name:
            continue
        kept.append(h)
    if len(kept) == len(hooks):
        continue
    if kept:
        node["hooks-libraries"] = kept
    else:
        node.pop("hooks-libraries", None)
    try:
        write_atomic(conf, json.dumps(cfg, indent=2))
    except Exception:
        pass
PYEOF

# --- Step 3: best-effort make the change live (guarded; never abort) ---
rm -rf /var/cache/opnsense/volt/* 2>/dev/null
[ -x /usr/local/sbin/configctl ] && /usr/local/sbin/configctl kea reload >/dev/null 2>&1
/usr/sbin/service configd restart >/dev/null 2>&1
exit 0
EOF
chmod +x "${BUILD_DIR}/+POST_INSTALL" "${BUILD_DIR}/+PRE_DEINSTALL"

# --- 6. Manifest & Packing List ---
cat << EOF > "${BUILD_DIR}/+MANIFEST"
name: ${PLUGIN_NAME}
version: "${VERSION}"
origin: opnsense/${PLUGIN_NAME}
comment: Kea DHCP to Unbound DNS dynamic registration
desc: Integrates Kea DHCPv4/v6 with Unbound DNS (Robust & Persistent)
maintainer: james@jmuk.net
www: https://github.com/JameZUK/os-kea-unbound
prefix: /
categories: [sysutils]
licenselogic: single
licenses: [BSD2CLAUSE]
EOF

cat << EOF > "${BUILD_DIR}/plist"
/usr/local/bin/keaunbound-status
/usr/local/share/kea/scripts/kea-unbound-hook.sh
/usr/local/etc/inc/plugins.inc.d/keaunbound.inc
/usr/local/etc/rc.syshook.d/update/50-keaunbound-repair
/usr/local/etc/rc.syshook.d/early/50-keaunbound-repair
/usr/local/etc/rc.syshook.d/start/50-keaunbound-replay
/usr/local/etc/newsyslog.conf.d/keaunbound.conf
EOF

echo ">>> Building Package..."
pkg create -m "${BUILD_DIR}" -r "${STAGE_DIR}" -p "${BUILD_DIR}/plist" -o .

echo "--------------------------------------------------------"
echo " Build Complete!"
echo " 1. REMOVE OLD: pkg delete os-kea-unbound"
echo " 2. INSTALL:    pkg add ./${PLUGIN_NAME}-${VERSION}.pkg"
echo " 3. LOGS:       tail -f /var/log/kea-unbound.log"
echo "--------------------------------------------------------"
