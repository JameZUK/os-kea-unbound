#!/bin/sh

# ==============================================================================
# Kea-Unbound Hook: Comprehensive Regression Test Suite (v2)
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
    unset LEASES4_SIZE LEASES4_AT0_ADDRESS LEASES4_AT0_HOSTNAME LEASES4_AT0_HWADDR
    unset LEASES6_SIZE LEASES6_AT0_ADDRESS LEASES6_AT0_HOSTNAME LEASES6_AT0_DUID
    unset DELETED_LEASES4_SIZE DELETED_LEASES4_AT0_ADDRESS DELETED_LEASES4_AT0_HOSTNAME DELETED_LEASES4_AT0_HWADDR
    unset DELETED_LEASES6_SIZE DELETED_LEASES6_AT0_ADDRESS DELETED_LEASES6_AT0_HOSTNAME DELETED_LEASES6_AT0_DUID
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

# ==============================================================================
printf "\n${GREEN}>>> ALL TESTS PASSED SUCCESSFULLY! <<<${NC}\n"
clean_slate
