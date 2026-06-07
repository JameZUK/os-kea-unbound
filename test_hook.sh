#!/bin/sh

# ==============================================================================
# Kea-Unbound Hook: Comprehensive Regression Test Suite (v6)
# Covers every Kea run_script callout, static-reservation guard (issue #6),
# per-subnet/per-reservation domain lookup (issue #7), static-A-survives-
# dynamic-AAAA preservation, independent forward/PTR guards (issue #11),
# and add idempotency / duplicate-log suppression (issue #10).
# ==============================================================================

# --- CONFIGURATION ---
HOOK_SCRIPT="/usr/local/share/kea/scripts/kea-unbound-hook.sh"
DOMAIN=$(hostname -d 2>/dev/null || echo "home.arpa")
[ -z "$DOMAIN" ] && DOMAIN="home.arpa"
HOST="test-stress"
FQDN="$HOST.$DOMAIN"
IP4="192.0.2.155"        # TEST-NET-1 (Safe)
IP6="2001:db8::155"      # Documentation Prefix (Safe)
MAC="aa:bb:cc:dd:ee:ff"
DUID="00:01:00:01:aa:bb"

# Colors (using printf compatible codes)
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m" # No Color

echo ">>> TARGET: $FQDN"
echo ">>> HOOK:   $HOOK_SCRIPT"
echo "-----------------------------------------------------"

# --- PREREQUISITES ---
printf "Checking python3... "
if /usr/local/bin/python3 -c "import ipaddress" 2>/dev/null; then
    printf "OK\n"
else
    printf "FAILED\n"
    echo "ERROR: python3 with ipaddress module is required at /usr/local/bin/python3"
    echo "IPv6 PTR tests will produce incorrect results without it."
    exit 1
fi

# --- HELPER FUNCTIONS ---

reverse_ipv4() { echo "$1" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}'; }
reverse_ipv6() { /usr/local/bin/python3 -c "import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]).reverse_pointer)" "$1"; }

IP4_PTR=$(reverse_ipv4 "$IP4")
IP6_PTR=$(reverse_ipv6 "$IP6")

clean_env() {
    unset LEASE4_ADDRESS LEASE4_HOSTNAME LEASE4_HWADDR
    unset LEASE6_ADDRESS LEASE6_HOSTNAME LEASE6_DUID
    unset LEASES4_SIZE LEASES6_SIZE DELETED_LEASES4_SIZE DELETED_LEASES6_SIZE
    local i=0
    while [ $i -lt 4 ]; do
        unset LEASES4_AT${i}_ADDRESS LEASES4_AT${i}_HOSTNAME LEASES4_AT${i}_HWADDR
        unset LEASES6_AT${i}_ADDRESS LEASES6_AT${i}_HOSTNAME LEASES6_AT${i}_DUID
        unset DELETED_LEASES4_AT${i}_ADDRESS DELETED_LEASES4_AT${i}_HOSTNAME DELETED_LEASES4_AT${i}_HWADDR
        unset DELETED_LEASES6_AT${i}_ADDRESS DELETED_LEASES6_AT${i}_HOSTNAME DELETED_LEASES6_AT${i}_DUID
        i=$((i + 1))
    done
}

clean_slate() {
    clean_env
    unbound-control -c /var/unbound/unbound.conf local_data_remove "$FQDN" >/dev/null 2>&1
    unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP4_PTR" >/dev/null 2>&1
    unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP6_PTR" >/dev/null 2>&1
    # Also clean up any old-style raw IP entries from previous versions
    unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP4" >/dev/null 2>&1
    unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP6" >/dev/null 2>&1
}

assert_exists() {
    TYPE=$1
    IP=$2
    RES=$(drill -Q -t $TYPE "$FQDN" @127.0.0.1 | grep "$IP")
    if [ -n "$RES" ]; then
        printf "${GREEN}[PASS]${NC} Found $TYPE record: $IP\n"
    else
        printf "${RED}[FAIL]${NC} MISSING $TYPE record: $IP\n"
        drill -t $TYPE "$FQDN" @127.0.0.1
        exit 1
    fi
}

assert_missing() {
    TYPE=$1
    IP=$2
    RES=$(drill -Q -t $TYPE "$FQDN" @127.0.0.1 | grep -v "^;" | grep -v "^$")
    if [ -z "$RES" ]; then
        printf "${GREEN}[PASS]${NC} $TYPE record correctly removed.\n"
    else
        if [ -n "$IP" ] && echo "$RES" | grep -q "$IP"; then
            printf "${RED}[FAIL]${NC} $TYPE record STILL EXISTS ($IP)!\n"
            exit 1
        elif [ -n "$IP" ]; then
             printf "${GREEN}[PASS]${NC} $TYPE record removed (different IP found, acceptable).\n"
        else
             printf "${RED}[FAIL]${NC} $TYPE record STILL EXISTS!\n"
             exit 1
        fi
    fi
}

assert_ptr_exists() {
    local IP="$1" EXPECTED="$2"
    local RES=$(drill -Q -x "$IP" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | head -n 1)
    if echo "$RES" | grep -qi "$EXPECTED"; then
        printf "${GREEN}[PASS]${NC} PTR record for $IP -> $EXPECTED\n"
    else
        printf "${RED}[FAIL]${NC} MISSING PTR for $IP (expected $EXPECTED, got: $RES)\n"
        drill -x "$IP" @127.0.0.1
        exit 1
    fi
}

assert_ptr_missing() {
    local IP="$1"
    local RES=$(drill -Q -x "$IP" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | head -n 1)
    if [ -z "$RES" ]; then
        printf "${GREEN}[PASS]${NC} PTR record for $IP correctly removed.\n"
    else
        printf "${RED}[FAIL]${NC} PTR for $IP STILL EXISTS: $RES\n"
        exit 1
    fi
}

_set_v4_vars() {
    local ACTION="$1" CUSTOM_HOST="$2"
    case "$ACTION" in
        leases4_committed)
            export LEASES4_SIZE=1
            export LEASES4_AT0_ADDRESS="$IP4"
            export LEASES4_AT0_HOSTNAME="$CUSTOM_HOST"
            export LEASES4_AT0_HWADDR="$MAC"
            ;;
        *)
            export LEASE4_ADDRESS="$IP4"
            export LEASE4_HOSTNAME="$CUSTOM_HOST"
            export LEASE4_HWADDR="$MAC"
            ;;
    esac
}

_set_v6_vars() {
    local ACTION="$1" CUSTOM_HOST="$2"
    case "$ACTION" in
        leases6_committed)
            export LEASES6_SIZE=1
            export LEASES6_AT0_ADDRESS="$IP6"
            export LEASES6_AT0_HOSTNAME="$CUSTOM_HOST"
            export LEASES6_AT0_DUID="$DUID"
            ;;
        *)
            export LEASE6_ADDRESS="$IP6"
            export LEASE6_HOSTNAME="$CUSTOM_HOST"
            export LEASE6_DUID="$DUID"
            ;;
    esac
}

trigger_v4() {
    ACTION=$1
    clean_env
    _set_v4_vars "$ACTION" "$HOST"
    printf " -> Triggering IPv4 $ACTION...\n"
    $HOOK_SCRIPT "$ACTION" >/dev/null
}

trigger_v4_raw() {
    local ACTION="$1" CUSTOM_HOST="$2"
    clean_env
    _set_v4_vars "$ACTION" "$CUSTOM_HOST"
    printf " -> Triggering IPv4 $ACTION (hostname='$CUSTOM_HOST')...\n"
    $HOOK_SCRIPT "$ACTION" >/dev/null
}

trigger_v4_committed_with_deleted() {
    local ADD_IP="$1" DEL_IP="$2"
    clean_env
    export LEASES4_SIZE=1
    export LEASES4_AT0_ADDRESS="$ADD_IP"
    export LEASES4_AT0_HOSTNAME="$HOST"
    export LEASES4_AT0_HWADDR="$MAC"
    if [ -n "$DEL_IP" ]; then
        export DELETED_LEASES4_SIZE=1
        export DELETED_LEASES4_AT0_ADDRESS="$DEL_IP"
        export DELETED_LEASES4_AT0_HOSTNAME="$HOST"
        export DELETED_LEASES4_AT0_HWADDR="$MAC"
        printf " -> Triggering IPv4 leases4_committed (add=$ADD_IP, deleted=$DEL_IP)...\n"
    else
        printf " -> Triggering IPv4 leases4_committed (add=$ADD_IP)...\n"
    fi
    $HOOK_SCRIPT leases4_committed >/dev/null
}

trigger_v6() {
    ACTION=$1
    clean_env
    _set_v6_vars "$ACTION" "$HOST"
    printf " -> Triggering IPv6 $ACTION...\n"
    $HOOK_SCRIPT "$ACTION" >/dev/null
}

trigger_v6_committed_with_deleted() {
    local ADD_IP="$1" DEL_IP="$2"
    clean_env
    export LEASES6_SIZE=1
    export LEASES6_AT0_ADDRESS="$ADD_IP"
    export LEASES6_AT0_HOSTNAME="$HOST"
    export LEASES6_AT0_DUID="$DUID"
    if [ -n "$DEL_IP" ]; then
        export DELETED_LEASES6_SIZE=1
        export DELETED_LEASES6_AT0_ADDRESS="$DEL_IP"
        export DELETED_LEASES6_AT0_HOSTNAME="$HOST"
        export DELETED_LEASES6_AT0_DUID="$DUID"
        printf " -> Triggering IPv6 leases6_committed (add=$ADD_IP, deleted=$DEL_IP)...\n"
    else
        printf " -> Triggering IPv6 leases6_committed (add=$ADD_IP)...\n"
    fi
    $HOOK_SCRIPT leases6_committed >/dev/null
}

# Args: "<hostname>|<ip>|<mac>" pairs (| separator to avoid colons in MACs)
trigger_v4_multi_committed() {
    clean_env
    local count=0 triple h ip m
    for triple in "$@"; do
        h=$(echo "$triple" | cut -d'|' -f1)
        ip=$(echo "$triple" | cut -d'|' -f2)
        m=$(echo "$triple" | cut -d'|' -f3)
        eval "export LEASES4_AT${count}_ADDRESS=\"\$ip\""
        eval "export LEASES4_AT${count}_HOSTNAME=\"\$h\""
        eval "export LEASES4_AT${count}_HWADDR=\"\$m\""
        count=$((count + 1))
    done
    export LEASES4_SIZE=$count
    printf " -> Triggering IPv4 leases4_committed (%d leases)...\n" "$count"
    $HOOK_SCRIPT leases4_committed >/dev/null
}

# ==============================================================================
# TEST SUITE
# ==============================================================================

# --- TEST 1 ---
printf "\n${YELLOW}TEST 1: IPv4 Single Stack Lifecycle${NC}\n"
clean_slate
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
assert_missing "AAAA"
assert_ptr_missing "$IP6"
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"
assert_ptr_missing "$IP4"
assert_missing "AAAA"

# --- TEST 2 ---
printf "\n${YELLOW}TEST 2: IPv6 Single Stack Lifecycle${NC}\n"
clean_slate
trigger_v6 "leases6_committed"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP6" "$FQDN"
assert_missing "A"
assert_ptr_missing "$IP4"
trigger_v6 "lease6_release"
assert_missing "AAAA" "$IP6"
assert_ptr_missing "$IP6"
assert_missing "A"

# --- TEST 3 ---
printf "\n${YELLOW}TEST 3: Dual Stack (Order: v4 -> v6)${NC}\n"
printf "${YELLOW}        Validates that adding v6 PRESERVES v4${NC}\n"
clean_slate
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
trigger_v6 "leases6_committed"
assert_exists "AAAA" "$IP6"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
assert_ptr_exists "$IP6" "$FQDN"

printf "${YELLOW}        Validates Partial Removal (Remove v4, Keep v6)${NC}\n"
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"
assert_ptr_missing "$IP4"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP6" "$FQDN"
trigger_v6 "lease6_release"
assert_missing "AAAA"
assert_ptr_missing "$IP6"

# --- TEST 4 ---
printf "\n${YELLOW}TEST 4: Dual Stack (Order: v6 -> v4)${NC}\n"
printf "${YELLOW}        Validates that adding v4 PRESERVES v6${NC}\n"
clean_slate
trigger_v6 "leases6_committed"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP6" "$FQDN"
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP4" "$FQDN"
assert_ptr_exists "$IP6" "$FQDN"

printf "${YELLOW}        Validates Partial Removal (Remove v6, Keep v4)${NC}\n"
trigger_v6 "lease6_release"
assert_missing "AAAA" "$IP6"
assert_ptr_missing "$IP6"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
trigger_v4 "lease4_release"
assert_missing "A"
assert_ptr_missing "$IP4"

# --- TEST 5 ---
printf "\n${YELLOW}TEST 5: Hostname Normalization${NC}\n"

printf "${YELLOW}  5a: Uppercase hostname -> lowercase${NC}\n"
HOST="TEST-STRESS"
FQDN="test-stress.$DOMAIN"
clean_slate
trigger_v4_raw "leases4_committed" "TEST-STRESS"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
trigger_v4_raw "lease4_release" "TEST-STRESS"
assert_missing "A" "$IP4"

printf "${YELLOW}  5b: FQDN input -> stripped to hostname${NC}\n"
HOST="test-stress"
FQDN="test-stress.$DOMAIN"
clean_slate
trigger_v4_raw "leases4_committed" "test-stress.example.com"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
trigger_v4_raw "lease4_release" "test-stress.example.com"
assert_missing "A" "$IP4"

printf "${YELLOW}  5c: Special characters stripped${NC}\n"
FQDN="teststress.$DOMAIN"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$FQDN" >/dev/null 2>&1
unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP4_PTR" >/dev/null 2>&1
trigger_v4_raw "leases4_committed" "test_stress!@#"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
trigger_v4_raw "lease4_release" "test_stress!@#"
assert_missing "A" "$IP4"
assert_ptr_missing "$IP4"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$FQDN" >/dev/null 2>&1

# --- TEST 6 ---
printf "\n${YELLOW}TEST 6: MAC Address Fallback (Empty Hostname)${NC}\n"
MAC_HOST="device-$(echo "$MAC" | tr ':' '-')"
FQDN="$MAC_HOST.$DOMAIN"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$FQDN" >/dev/null 2>&1
unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP4_PTR" >/dev/null 2>&1
trigger_v4_raw "leases4_committed" ""
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
trigger_v4_raw "lease4_release" ""
assert_missing "A" "$IP4"
assert_ptr_missing "$IP4"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$FQDN" >/dev/null 2>&1

# Restore defaults
HOST="test-stress"
FQDN="$HOST.$DOMAIN"

# --- TEST 7 ---
printf "\n${YELLOW}TEST 7: lease6_rebind Registers AAAA${NC}\n"
printf "${YELLOW}        Validates that a v6 rebind (not just renew) refreshes DNS${NC}\n"
clean_slate
trigger_v6 "lease6_rebind"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP6" "$FQDN"
trigger_v6 "lease6_release"
assert_missing "AAAA" "$IP6"
assert_ptr_missing "$IP6"

# --- TEST 8 ---
printf "\n${YELLOW}TEST 8: leases4_committed with DELETED_LEASES4 (IP reassignment)${NC}\n"
printf "${YELLOW}        Validates that Kea's DELETED_LEASES4_* entries trigger a remove${NC}\n"
OLD_IP="192.0.2.200"
OLD_PTR=$(reverse_ipv4 "$OLD_IP")
clean_slate
unbound-control -c /var/unbound/unbound.conf local_data_remove "$OLD_PTR" >/dev/null 2>&1
# Seed an existing record at OLD_IP so we can confirm it is cleared.
trigger_v4_committed_with_deleted "$OLD_IP" ""
assert_exists "A" "$OLD_IP"
# Now Kea reassigns: commits IP4 for the same host and reports OLD_IP as deleted.
trigger_v4_committed_with_deleted "$IP4" "$OLD_IP"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
# Cleanup
trigger_v4 "lease4_release"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$OLD_PTR" >/dev/null 2>&1

# --- TEST 9 ---
printf "\n${YELLOW}TEST 9: lease4_renew adds record (belt-and-braces path)${NC}\n"
clean_slate
trigger_v4 "lease4_renew"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"
assert_ptr_missing "$IP4"

# --- TEST 10 ---
printf "\n${YELLOW}TEST 10: lease4_expire removes record${NC}\n"
clean_slate
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
trigger_v4 "lease4_expire"
assert_missing "A" "$IP4"
assert_ptr_missing "$IP4"

# --- TEST 11 ---
printf "\n${YELLOW}TEST 11: lease4_decline removes record${NC}\n"
clean_slate
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
trigger_v4 "lease4_decline"
assert_missing "A" "$IP4"
assert_ptr_missing "$IP4"

# --- TEST 12 ---
printf "\n${YELLOW}TEST 12: lease6_renew adds record (belt-and-braces path)${NC}\n"
clean_slate
trigger_v6 "lease6_renew"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP6" "$FQDN"
trigger_v6 "lease6_release"
assert_missing "AAAA" "$IP6"
assert_ptr_missing "$IP6"

# --- TEST 13 ---
printf "\n${YELLOW}TEST 13: lease6_expire removes record${NC}\n"
clean_slate
trigger_v6 "leases6_committed"
assert_exists "AAAA" "$IP6"
trigger_v6 "lease6_expire"
assert_missing "AAAA" "$IP6"
assert_ptr_missing "$IP6"

# --- TEST 14 ---
printf "\n${YELLOW}TEST 14: lease6_decline removes record${NC}\n"
clean_slate
trigger_v6 "leases6_committed"
assert_exists "AAAA" "$IP6"
trigger_v6 "lease6_decline"
assert_missing "AAAA" "$IP6"
assert_ptr_missing "$IP6"

# --- TEST 15 ---
printf "\n${YELLOW}TEST 15: leases6_committed with DELETED_LEASES6 (IPv6 IP reassignment)${NC}\n"
OLD_IP6="2001:db8::dead"
OLD_IP6_PTR=$(reverse_ipv6 "$OLD_IP6")
clean_slate
unbound-control -c /var/unbound/unbound.conf local_data_remove "$OLD_IP6_PTR" >/dev/null 2>&1
# Seed: host at OLD_IP6
trigger_v6_committed_with_deleted "$OLD_IP6" ""
assert_exists "AAAA" "$OLD_IP6"
# Reassign: host now at IP6, Kea reports OLD_IP6 as deleted
trigger_v6_committed_with_deleted "$IP6" "$OLD_IP6"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP6" "$FQDN"
assert_ptr_missing "$OLD_IP6"
# Cleanup
trigger_v6 "lease6_release"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$OLD_IP6_PTR" >/dev/null 2>&1

# --- TEST 16 ---
printf "\n${YELLOW}TEST 16: Multi-lease leases4_committed (LEASES4_SIZE=2)${NC}\n"
M_HOST1="multi-a"
M_HOST2="multi-b"
M_FQDN1="$M_HOST1.$DOMAIN"
M_FQDN2="$M_HOST2.$DOMAIN"
M_IP1="192.0.2.111"
M_IP2="192.0.2.112"
M_PTR1=$(reverse_ipv4 "$M_IP1")
M_PTR2=$(reverse_ipv4 "$M_IP2")
for n in "$M_FQDN1" "$M_FQDN2" "$M_PTR1" "$M_PTR2"; do
    unbound-control -c /var/unbound/unbound.conf local_data_remove "$n" >/dev/null 2>&1
done
trigger_v4_multi_committed \
    "$M_HOST1|$M_IP1|aa:aa:aa:aa:aa:01" \
    "$M_HOST2|$M_IP2|aa:aa:aa:aa:aa:02"
RES1=$(drill -Q -t A "$M_FQDN1" @127.0.0.1 | grep "$M_IP1")
RES2=$(drill -Q -t A "$M_FQDN2" @127.0.0.1 | grep "$M_IP2")
if [ -n "$RES1" ] && [ -n "$RES2" ]; then
    printf "${GREEN}[PASS]${NC} Both leases registered ($M_FQDN1, $M_FQDN2)\n"
else
    printf "${RED}[FAIL]${NC} Multi-lease registration incomplete: host1='%s' host2='%s'\n" "$RES1" "$RES2"
    exit 1
fi
PTR1=$(drill -Q -x "$M_IP1" @127.0.0.1 | grep -i "$M_HOST1")
PTR2=$(drill -Q -x "$M_IP2" @127.0.0.1 | grep -i "$M_HOST2")
if [ -n "$PTR1" ] && [ -n "$PTR2" ]; then
    printf "${GREEN}[PASS]${NC} Both PTR records present\n"
else
    printf "${RED}[FAIL]${NC} Multi-lease PTR missing: ptr1='%s' ptr2='%s'\n" "$PTR1" "$PTR2"
    exit 1
fi
for n in "$M_FQDN1" "$M_FQDN2" "$M_PTR1" "$M_PTR2"; do
    unbound-control -c /var/unbound/unbound.conf local_data_remove "$n" >/dev/null 2>&1
done

# --- TEST 17 ---
printf "\n${YELLOW}TEST 17: Dual-stack IP update (v4 changes, v6 preserved)${NC}\n"
NEW_IP4="192.0.2.177"
NEW_IP4_PTR=$(reverse_ipv4 "$NEW_IP4")
clean_slate
unbound-control -c /var/unbound/unbound.conf local_data_remove "$NEW_IP4_PTR" >/dev/null 2>&1
# Establish dual-stack
trigger_v4 "leases4_committed"
trigger_v6 "leases6_committed"
assert_exists "A" "$IP4"
assert_exists "AAAA" "$IP6"
# v4 address changes for the same host; v6 must survive
trigger_v4_committed_with_deleted "$NEW_IP4" "$IP4"
assert_exists "A" "$NEW_IP4"
assert_missing "A" "$IP4"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$NEW_IP4" "$FQDN"
assert_ptr_exists "$IP6" "$FQDN"
assert_ptr_missing "$IP4"
# Cleanup
trigger_v4 "lease4_release"
trigger_v6 "lease6_release"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$NEW_IP4_PTR" >/dev/null 2>&1

# --- TEST 18 ---
printf "\n${YELLOW}TEST 18: Idempotent release (no prior record)${NC}\n"
clean_slate
# Release for a host we never committed -- must not error or corrupt state
trigger_v4 "lease4_release"
trigger_v6 "lease6_release"
# System still responsive: a following commit still works
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"

# --- TEST 19 ---
printf "\n${YELLOW}TEST 19: Unknown hook name is a safe no-op${NC}\n"
clean_slate
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
clean_env
export LEASE4_ADDRESS="$IP4"
export LEASE4_HOSTNAME="$HOST"
export LEASE4_HWADDR="$MAC"
printf " -> Triggering unknown hook 'nonexistent_callout'...\n"
if $HOOK_SCRIPT "nonexistent_callout" >/dev/null 2>&1; then
    printf "${GREEN}[PASS]${NC} Unknown hook exited 0\n"
else
    printf "${RED}[FAIL]${NC} Unknown hook exited non-zero\n"
    exit 1
fi
# Existing state must be intact
assert_exists "A" "$IP4"
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"

# --- TEST 20 ---
printf "\n${YELLOW}TEST 20: Empty leases4_committed (LEASES4_SIZE=0) is a no-op${NC}\n"
clean_slate
clean_env
export LEASES4_SIZE=0
printf " -> Triggering IPv4 leases4_committed with 0 leases...\n"
$HOOK_SCRIPT leases4_committed >/dev/null
assert_missing "A" "$IP4"
assert_ptr_missing "$IP4"

# ==============================================================================
# Issue #6: static-reservation guard
# Issue #7: per-subnet / per-reservation domain
# ==============================================================================

# Fixture paths used by the new tests. The hook reads these from env vars
# (defaults to /var/unbound/host_entries.conf and the real Kea configs).
TEST_HOST_ENTRIES="/tmp/test-kea-unbound-host_entries.conf"
TEST_KEA4="/tmp/test-kea-unbound-dhcp4.conf"
TEST_KEA6="/tmp/test-kea-unbound-dhcp6.conf"

cleanup_fixtures() {
    rm -f "$TEST_HOST_ENTRIES" "$TEST_KEA4" "$TEST_KEA6"
    unset HOST_ENTRIES KEA_DHCP4_CONF KEA_DHCP6_CONF
}
trap cleanup_fixtures EXIT INT TERM

# --- TEST 21 ---
printf "\n${YELLOW}TEST 21: Issue #6 — static reservation in host_entries.conf is preserved${NC}\n"
printf "${YELLOW}        Validates that hook skips BOTH add and remove for static FQDNs${NC}\n"
clean_slate
HOST="test-stress"
FQDN="$HOST.$DOMAIN"
# Simulate Unbound having loaded host_entries.conf at startup.
unbound-control -c /var/unbound/unbound.conf local_data "$FQDN IN A $IP4" >/dev/null 2>&1
unbound-control -c /var/unbound/unbound.conf local_data "$IP4_PTR PTR $FQDN" >/dev/null 2>&1
# Sentinel matching the typical OPNsense Register-DHCP-Static-Mappings format.
cat > "$TEST_HOST_ENTRIES" <<HE
local-data: "$FQDN. 3600 IN A $IP4"
local-data-ptr: "$IP4 $FQDN"
HE
export HOST_ENTRIES="$TEST_HOST_ENTRIES"

# Lease release MUST NOT wipe the static A/PTR.
trigger_v4 "lease4_release"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"

# Lease commit (re-add) MUST also be a no-op — the static is authoritative.
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"

# Cleanup
unset HOST_ENTRIES
rm -f "$TEST_HOST_ENTRIES"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$FQDN" >/dev/null 2>&1
unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP4_PTR" >/dev/null 2>&1

# --- TEST 22 ---
printf "\n${YELLOW}TEST 22: Issue #7 — per-reservation domain (matched by IP)${NC}\n"
RES_DOMAIN_IP="cam.example.lan"
RES_FQDN="$HOST.$RES_DOMAIN_IP"
RES_FQDN_PTR_TARGET="$RES_FQDN"
cat > "$TEST_KEA4" <<KEA
{
  "Dhcp4": {
    "subnet4": [{
      "subnet": "192.0.2.0/24",
      "reservations": [{
        "ip-address": "$IP4",
        "hw-address": "$MAC",
        "option-data": [{"name": "domain-name", "data": "$RES_DOMAIN_IP"}]
      }]
    }]
  }
}
KEA
export KEA_DHCP4_CONF="$TEST_KEA4"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$RES_FQDN" >/dev/null 2>&1
clean_slate
FQDN="$RES_FQDN"
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$RES_FQDN_PTR_TARGET"
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"
unset KEA_DHCP4_CONF
rm -f "$TEST_KEA4"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$RES_FQDN" >/dev/null 2>&1

# --- TEST 23 ---
printf "\n${YELLOW}TEST 23: Issue #7 — per-reservation domain (matched by hw-address, no IP pin)${NC}\n"
HW_DOMAIN="hwmatch.example.lan"
HW_FQDN="$HOST.$HW_DOMAIN"
# Reservation has NO ip-address; IP is also outside the subnet, so subnet
# CIDR match must NOT trigger. Only the hw-address match should fire.
cat > "$TEST_KEA4" <<KEA
{
  "Dhcp4": {
    "subnet4": [{
      "subnet": "10.99.99.0/24",
      "reservations": [{
        "hw-address": "$MAC",
        "option-data": [{"name": "domain-name", "data": "$HW_DOMAIN"}]
      }]
    }]
  }
}
KEA
export KEA_DHCP4_CONF="$TEST_KEA4"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$HW_FQDN" >/dev/null 2>&1
clean_slate
FQDN="$HW_FQDN"
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$HW_FQDN"
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"
unset KEA_DHCP4_CONF
rm -f "$TEST_KEA4"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$HW_FQDN" >/dev/null 2>&1

# --- TEST 24 ---
printf "\n${YELLOW}TEST 24: Issue #7 — per-subnet domain (CIDR match, no reservation)${NC}\n"
SUB_DOMAIN="subnet.example.lan"
SUB_FQDN="$HOST.$SUB_DOMAIN"
cat > "$TEST_KEA4" <<KEA
{
  "Dhcp4": {
    "subnet4": [{
      "subnet": "192.0.2.0/24",
      "option-data": [{"name": "domain-name", "data": "$SUB_DOMAIN"}]
    }]
  }
}
KEA
export KEA_DHCP4_CONF="$TEST_KEA4"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$SUB_FQDN" >/dev/null 2>&1
clean_slate
FQDN="$SUB_FQDN"
trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$SUB_FQDN"
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"
unset KEA_DHCP4_CONF
rm -f "$TEST_KEA4"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$SUB_FQDN" >/dev/null 2>&1

# --- TEST 25 ---
printf "\n${YELLOW}TEST 25: Issue #7 — IPv6 per-reservation domain (matched by ip-addresses + duid)${NC}\n"
V6_DOMAIN="v6res.example.lan"
V6_FQDN="$HOST.$V6_DOMAIN"
cat > "$TEST_KEA6" <<KEA
{
  "Dhcp6": {
    "subnet6": [{
      "subnet": "2001:db8::/32",
      "reservations": [{
        "ip-addresses": ["$IP6"],
        "duid": "$DUID",
        "option-data": [{"name": "domain-name", "data": "$V6_DOMAIN"}]
      }]
    }]
  }
}
KEA
export KEA_DHCP6_CONF="$TEST_KEA6"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$V6_FQDN" >/dev/null 2>&1
clean_slate
FQDN="$V6_FQDN"
trigger_v6 "leases6_committed"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP6" "$V6_FQDN"
trigger_v6 "lease6_release"
assert_missing "AAAA" "$IP6"
unset KEA_DHCP6_CONF
rm -f "$TEST_KEA6"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$V6_FQDN" >/dev/null 2>&1

# Restore globals
HOST="test-stress"
FQDN="$HOST.$DOMAIN"

# --- TEST 26 ---
printf "\n${YELLOW}TEST 26: Static A preserved across dynamic AAAA event${NC}\n"
printf "${YELLOW}        Regression: local_data_remove during a v6 event must not${NC}\n"
printf "${YELLOW}        permanently wipe a static A loaded from host_entries.conf${NC}\n"
clean_slate
# Simulate Unbound having loaded host_entries.conf at startup.
unbound-control -c /var/unbound/unbound.conf local_data "$FQDN IN A $IP4" >/dev/null 2>&1
unbound-control -c /var/unbound/unbound.conf local_data "$IP4_PTR PTR $FQDN" >/dev/null 2>&1
cat > "$TEST_HOST_ENTRIES" <<HE
local-data: "$FQDN. 3600 IN A $IP4"
local-data-ptr: "$IP4 $FQDN"
HE
export HOST_ENTRIES="$TEST_HOST_ENTRIES"

# Dynamic v6 lease arrives — AAAA must register AND static A must survive.
trigger_v6 "leases6_committed"
assert_exists "AAAA" "$IP6"
assert_ptr_exists "$IP6" "$FQDN"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"

# v6 release must also leave the static A intact.
trigger_v6 "lease6_release"
assert_missing "AAAA" "$IP6"
assert_ptr_missing "$IP6"
assert_exists "A" "$IP4"
assert_ptr_exists "$IP4" "$FQDN"

# Cleanup
unset HOST_ENTRIES
rm -f "$TEST_HOST_ENTRIES"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$FQDN" >/dev/null 2>&1
unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP4_PTR" >/dev/null 2>&1

# --- TEST 27 ---
printf "\n${YELLOW}TEST 27: Issue #11 — static PTR alone does NOT block forward A${NC}\n"
printf "${YELLOW}        Static PTR for an IP must not suppress an unrelated A record${NC}\n"
clean_slate
OTHER_HOST="static-owner.$DOMAIN"
# Seed Unbound with a static PTR pointing at a totally unrelated FQDN.
unbound-control -c /var/unbound/unbound.conf local_data "$IP4_PTR PTR $OTHER_HOST" >/dev/null 2>&1
# host_entries fixture has ONLY a static PTR — no static forward for OUR FQDN.
cat > "$TEST_HOST_ENTRIES" <<HE
local-data-ptr: "$IP4 $OTHER_HOST"
HE
export HOST_ENTRIES="$TEST_HOST_ENTRIES"

trigger_v4 "leases4_committed"
# Our forward A MUST register (this is the fix).
assert_exists "A" "$IP4"
# Static PTR MUST survive — we never touched it.
RES=$(drill -Q -x "$IP4" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | head -n 1)
if echo "$RES" | grep -qi "$OTHER_HOST"; then
    printf "${GREEN}[PASS]${NC} Static PTR preserved ($IP4 -> $OTHER_HOST)\n"
else
    printf "${RED}[FAIL]${NC} Static PTR for $IP4 was clobbered. Got: $RES\n"
    exit 1
fi

# Release must remove the dynamic forward but again leave the static PTR alone.
trigger_v4 "lease4_release"
assert_missing "A" "$IP4"
RES=$(drill -Q -x "$IP4" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | head -n 1)
if echo "$RES" | grep -qi "$OTHER_HOST"; then
    printf "${GREEN}[PASS]${NC} Static PTR preserved across release\n"
else
    printf "${RED}[FAIL]${NC} Static PTR for $IP4 lost on release. Got: $RES\n"
    exit 1
fi
unset HOST_ENTRIES
rm -f "$TEST_HOST_ENTRIES"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$IP4_PTR" >/dev/null 2>&1

# --- TEST 28 ---
printf "\n${YELLOW}TEST 28: Issue #11 — static forward alone does NOT block PTR${NC}\n"
printf "${YELLOW}        Static A for FQDN must not suppress dynamic PTR registration${NC}\n"
clean_slate
OTHER_IP="192.0.2.222"
# Seed Unbound with a static forward record pointing somewhere else.
unbound-control -c /var/unbound/unbound.conf local_data "$FQDN IN A $OTHER_IP" >/dev/null 2>&1
# host_entries fixture has ONLY the static forward — no static PTR for OUR IP.
cat > "$TEST_HOST_ENTRIES" <<HE
local-data: "$FQDN. 3600 IN A $OTHER_IP"
HE
export HOST_ENTRIES="$TEST_HOST_ENTRIES"

trigger_v4 "leases4_committed"
# Static forward MUST survive — we never touched it.
RES=$(drill -Q -t A "$FQDN" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | head -n 1)
if echo "$RES" | grep -q "$OTHER_IP"; then
    printf "${GREEN}[PASS]${NC} Static A preserved ($FQDN -> $OTHER_IP)\n"
else
    printf "${RED}[FAIL]${NC} Static A for $FQDN was clobbered. Got: $RES\n"
    exit 1
fi
# PTR for OUR IP MUST register (this is the fix).
assert_ptr_exists "$IP4" "$FQDN"

# Cleanup
trigger_v4 "lease4_release"
assert_ptr_missing "$IP4"
unset HOST_ENTRIES
rm -f "$TEST_HOST_ENTRIES"
unbound-control -c /var/unbound/unbound.conf local_data_remove "$FQDN" >/dev/null 2>&1

# --- TEST 29 ---
printf "\n${YELLOW}TEST 29: Issue #10 — repeat add is idempotent (no duplicate log)${NC}\n"
printf "${YELLOW}        leases*_committed + lease*_renew firing for same lease must${NC}\n"
printf "${YELLOW}        log only one 'Added' line, not two${NC}\n"
clean_slate
TEST_LOG="/tmp/test-kea-unbound.log"
: > "$TEST_LOG"
export LOG_FILE="$TEST_LOG"

trigger_v4 "leases4_committed"
assert_exists "A" "$IP4"
ADD_LINES_1=$(grep -c "Added A for $FQDN" "$TEST_LOG")

# Simulate the duplicate-fire: lease4_renew immediately after the commit.
trigger_v4 "lease4_renew"
ADD_LINES_2=$(grep -c "Added A for $FQDN" "$TEST_LOG")

# A second leases4_committed for the same lease (e.g. lease cache refresh).
trigger_v4 "leases4_committed"
ADD_LINES_3=$(grep -c "Added A for $FQDN" "$TEST_LOG")

if [ "$ADD_LINES_1" = "1" ] && [ "$ADD_LINES_2" = "1" ] && [ "$ADD_LINES_3" = "1" ]; then
    printf "${GREEN}[PASS]${NC} Idempotent: 1 add line after 3 add events\n"
else
    printf "${RED}[FAIL]${NC} Duplicate logs: after1=$ADD_LINES_1 after2=$ADD_LINES_2 after3=$ADD_LINES_3\n"
    echo "--- log contents ---"
    cat "$TEST_LOG"
    exit 1
fi

# Cleanup
trigger_v4 "lease4_release"
unset LOG_FILE
rm -f "$TEST_LOG"

# ==============================================================================
printf "\n${GREEN}>>> ALL 29 TEST CASES PASSED SUCCESSFULLY! <<<${NC}\n"
clean_slate
cleanup_fixtures
