#!/bin/sh

# 1. Define Variables
PLUGIN_NAME="os-kea-unbound"
VERSION="3.5.0"
BUILD_DIR="./${PLUGIN_NAME}_build"
STAGE_DIR="${BUILD_DIR}/stage"

echo ">>> Cleaning up old build directory..."
rm -rf "${BUILD_DIR}"
mkdir -p "${STAGE_DIR}"

# Mandated directories
KEA_SCRIPT_DIR="${STAGE_DIR}/usr/local/share/kea/scripts"
UPDATE_HOOK_DIR="${STAGE_DIR}/usr/local/etc/rc.syshook.d/update"
BOOT_HOOK_DIR="${STAGE_DIR}/usr/local/etc/rc.syshook.d/early"
LOG_ROT_DIR="${STAGE_DIR}/usr/local/etc/newsyslog.conf.d"

echo ">>> Creating directory structure..."
mkdir -p "${KEA_SCRIPT_DIR}" "${UPDATE_HOOK_DIR}" "${BOOT_HOOK_DIR}" "${LOG_ROT_DIR}"
mkdir -p "${STAGE_DIR}/usr/local/etc/inc/plugins.inc.d"

echo ">>> Generating Plugin Files..."

# --- 1. The DNS Hook Script ---
cat << 'EOF' > "${KEA_SCRIPT_DIR}/kea-unbound-hook.sh"
#!/bin/sh
LOG_FILE="/var/log/kea-unbound.log"
UNBOUND_CONF="/var/unbound/unbound.conf"
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
get_domain() { D=$(hostname -d 2>/dev/null); [ -z "$D" ] && echo "home.arpa" || echo "$D"; }
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
update_dns_entry() {
    local ACTION="$1" IP="$2" HOST="$3" IP_VER="$4"
    [ -z "$IP" ] && return
    HOST=$(normalize_hostname "$HOST"); [ -z "$HOST" ] && return
    local FQDN="$HOST.$(get_domain)"
    local THIS_TYPE="A"; local OTHER_TYPE="AAAA"; local OTHER_VER="6"
    [ "$IP_VER" = "6" ] && THIS_TYPE="AAAA" && OTHER_TYPE="A" && OTHER_VER="4"
    local PRESERVED_IP=$(drill -Q -t $OTHER_TYPE "$FQDN" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | awk '{print $NF}' | head -n 1)
    local PTR_NAME=$(get_ptr_name "$IP_VER" "$IP")
    uc local_data_remove "$FQDN"
    [ -n "$PTR_NAME" ] && uc local_data_remove "$PTR_NAME"
    if [ "$ACTION" = "add" ]; then
        uc local_data "$FQDN IN $THIS_TYPE $IP"
        [ -n "$PTR_NAME" ] && uc local_data "$PTR_NAME PTR $FQDN"
        log info "Added $THIS_TYPE for $FQDN ($IP) [PTR: ${PTR_NAME:-FAILED}]"
    else
        log info "Removed $THIS_TYPE for $FQDN ($IP) [PTR: ${PTR_NAME:-FAILED}]"
    fi
    if [ -n "$PRESERVED_IP" ]; then
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
            update_dns_entry "remove" "$ADDR" "$(host_or_mac_fallback "$HN" "$HW")" "4"
            i=$((i + 1))
        done
        i=0; SIZE="${LEASES4_SIZE:-0}"
        while [ "$i" -lt "$SIZE" ]; do
            ADDR=$(eval "echo \$LEASES4_AT${i}_ADDRESS")
            HN=$(eval "echo \$LEASES4_AT${i}_HOSTNAME")
            HW=$(eval "echo \$LEASES4_AT${i}_HWADDR")
            update_dns_entry "add" "$ADDR" "$(host_or_mac_fallback "$HN" "$HW")" "4"
            i=$((i + 1))
        done
        ;;
    lease4_renew)
        [ -n "$LEASE4_ADDRESS" ] && update_dns_entry "add" "$LEASE4_ADDRESS" "$(host_or_mac_fallback "$LEASE4_HOSTNAME" "$LEASE4_HWADDR")" "4"
        ;;
    lease4_release|lease4_expire|lease4_decline)
        [ -n "$LEASE4_ADDRESS" ] && update_dns_entry "remove" "$LEASE4_ADDRESS" "$(host_or_mac_fallback "$LEASE4_HOSTNAME" "$LEASE4_HWADDR")" "4"
        ;;
    leases6_committed)
        i=0; SIZE="${DELETED_LEASES6_SIZE:-0}"
        while [ "$i" -lt "$SIZE" ]; do
            ADDR=$(eval "echo \$DELETED_LEASES6_AT${i}_ADDRESS")
            HN=$(eval "echo \$DELETED_LEASES6_AT${i}_HOSTNAME")
            DUID=$(eval "echo \$DELETED_LEASES6_AT${i}_DUID")
            update_dns_entry "remove" "$ADDR" "$(host_or_mac_fallback "$HN" "$DUID")" "6"
            i=$((i + 1))
        done
        i=0; SIZE="${LEASES6_SIZE:-0}"
        while [ "$i" -lt "$SIZE" ]; do
            ADDR=$(eval "echo \$LEASES6_AT${i}_ADDRESS")
            HN=$(eval "echo \$LEASES6_AT${i}_HOSTNAME")
            DUID=$(eval "echo \$LEASES6_AT${i}_DUID")
            update_dns_entry "add" "$ADDR" "$(host_or_mac_fallback "$HN" "$DUID")" "6"
            i=$((i + 1))
        done
        ;;
    lease6_renew|lease6_rebind)
        [ -n "$LEASE6_ADDRESS" ] && update_dns_entry "add" "$LEASE6_ADDRESS" "$(host_or_mac_fallback "$LEASE6_HOSTNAME" "$LEASE6_DUID")" "6"
        ;;
    lease6_release|lease6_expire|lease6_decline)
        [ -n "$LEASE6_ADDRESS" ] && update_dns_entry "remove" "$LEASE6_ADDRESS" "$(host_or_mac_fallback "$LEASE6_HOSTNAME" "$LEASE6_DUID")" "6"
        ;;
esac
EOF
chmod 755 "${KEA_SCRIPT_DIR}/kea-unbound-hook.sh"

# --- 2. The Python Patcher Logic ---
PATCH_CMD='import os, shutil
files = [
    {"ctrl": "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings4.xml", "model": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml", "php": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php", "anchor": "dhcpv4.general.dhcp_socket_type", "prefix": "dhcpv4", "key": "Dhcp4"},
    {"ctrl": "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings6.xml", "model": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.xml", "php": "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.php", "anchor": "dhcpv6.general.fwrules", "prefix": "dhcpv6", "key": "Dhcp6"}
]
for fset in files:
    if not os.path.exists(fset["ctrl"]): continue
    for fpath in [fset["ctrl"], fset["model"], fset["php"]]:
        if not os.path.exists(fpath + ".bak"): shutil.copy2(fpath, fpath + ".bak")
    
    with open(fset["ctrl"], "r") as f: content = f.read()
    if "registerDynamicLeases" not in content:
        field = "    <field>\n        <id>" + fset["prefix"] + ".general.registerDynamicLeases</id>\n"
        field += "        <label>Register Leases in Unbound (via os-kea-unbound)</label>\n"
        field += "        <type>checkbox</type>\n        <help>Enable DNS registration (Plugin Feature).</help>\n    </field>\n"
        content = content.replace("<field>\n        <id>" + fset["anchor"], field + "    <field>\n        <id>" + fset["anchor"])
        with open(fset["ctrl"], "w") as f: f.write(content)

    with open(fset["model"], "r") as f: content = f.read()
    if "registerDynamicLeases" not in content:
        m_node = "            <registerDynamicLeases type=\"BooleanField\">\n                <default>0</default>\n            </registerDynamicLeases>\n"
        content = content.replace("</general>", m_node + "        </general>")
        with open(fset["model"], "w") as f: f.write(content)

    with open(fset["php"], "r") as f: content = f.read()
    if "kea-unbound-hook.sh" not in content:
        p_code = "        if ((string)$this->general->registerDynamicLeases === \"1\") {\n"
        p_code += "            if (!isset($cnf[\"" + fset["key"] + "\"][\"hooks-libraries\"])) $cnf[\"" + fset["key"] + "\"][\"hooks-libraries\"] = [];\n"
        p_code += "            $cnf[\"" + fset["key"] + "\"][\"hooks-libraries\"][] = [\"library\" => \"/usr/local/lib/kea/hooks/libdhcp_run_script.so\", \"parameters\" => [\"name\" => \"/usr/local/share/kea/scripts/kea-unbound-hook.sh\", \"sync\" => false]];\n"
        p_code += "        }\n"
        content = content.replace("File::file_put_contents", p_code + "        File::file_put_contents")
        with open(fset["php"], "w") as f: f.write(content)'

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
mkdir -p /usr/local/share/kea/scripts
chmod 755 /usr/local/share/kea /usr/local/share/kea/scripts
touch /var/log/kea-unbound.log
chmod 644 /var/log/kea-unbound.log
/usr/local/bin/python3 -c '$PATCH_CMD'
rm -rf /var/cache/opnsense/volt/*
/usr/sbin/service configd restart
echo "Plugin installed. Please go to Services > Kea DHCP > Settings."
EOF

cat << 'EOF' > "${BUILD_DIR}/+PRE_DEINSTALL"
#!/bin/sh
restore() { [ -f "$1.bak" ] && mv "$1.bak" "$1"; }
restore "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings4.xml"
restore "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml"
restore "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php"
restore "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings6.xml"
restore "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.xml"
restore "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.php"
/usr/sbin/service configd restart
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
/usr/local/share/kea/scripts/kea-unbound-hook.sh
/usr/local/etc/inc/plugins.inc.d/keaunbound.inc
/usr/local/etc/rc.syshook.d/update/50-keaunbound-repair
/usr/local/etc/rc.syshook.d/early/50-keaunbound-repair
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
