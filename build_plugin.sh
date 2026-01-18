#!/bin/sh

# 1. Define Variables
PLUGIN_NAME="os-kea-unbound"
VERSION="3.2" # Feature: Smart Updates + Dedicated Logging
BUILD_DIR="./${PLUGIN_NAME}_build"
STAGE_DIR="${BUILD_DIR}/stage"

echo ">>> Cleaning up old build directory..."
rm -rf "${BUILD_DIR}"
mkdir -p "${STAGE_DIR}"

# Define Kea's mandated script directory
KEA_SCRIPT_DIR="${STAGE_DIR}/usr/local/share/kea/scripts"

echo ">>> Creating directory structure..."
mkdir -p "${KEA_SCRIPT_DIR}"
mkdir -p "${STAGE_DIR}/usr/local/share/os-kea-unbound"
mkdir -p "${STAGE_DIR}/usr/local/etc/inc/plugins.inc.d"

echo ">>> Generating Plugin Files..."

# --- 1. The Smart Hook Script (v3.2) ---
cat << 'EOF' > "${KEA_SCRIPT_DIR}/kea-unbound-hook.sh"
#!/bin/sh
# Kea DHCPv4 & DHCPv6 Unbound DNS Hook (v3.2 - Smart Update & File Logging)

LOG_TAG="kea-unbound-hook"
LOG_FILE="/var/log/kea-unbound.log"
UNBOUND_CONF="/var/unbound/unbound.conf"

# Logging to dedicated file with timestamp
log() {
  local LEVEL="$1"
  local MSG="$2"
  local DT=$(date '+%Y-%m-%d %H:%M:%S')
  echo "$DT [$LEVEL] $MSG" >> "$LOG_FILE"
}

normalize_hostname() {
  echo "$1" | tr 'A-Z' 'a-z' | sed 's/\..*//' | sed 's/[^a-z0-9-]//g'
}

get_domain() {
  D=$(hostname -d 2>/dev/null)
  [ -z "$D" ] && echo "home.arpa" || echo "$D"
}

update_dns_entry() {
    local ACTION="$1"     # add or remove
    local IP="$2"
    local HOST="$3"
    local IP_VER="$4"     # 4 or 6

    # Validation
    [ -z "$IP" ] && return
    HOST=$(normalize_hostname "$HOST")
    [ -z "$HOST" ] && return
    
    local DOMAIN=$(get_domain)
    local FQDN="$HOST.$DOMAIN"
    
    # Determine Types
    local THIS_TYPE=""
    local OTHER_TYPE=""
    
    if [ "$IP_VER" = "6" ]; then
        THIS_TYPE="AAAA"
        OTHER_TYPE="A"
    else
        THIS_TYPE="A"
        OTHER_TYPE="AAAA"
    fi

    log debug "Processing $ACTION for $FQDN ($THIS_TYPE $IP)"

    # PRESERVE STEP: Check if the *other* record type exists
    # We grep for the answer section and use awk to grab strictly the IP address
    local PRESERVED_IP=""
    PRESERVED_IP=$(drill -Q -t $OTHER_TYPE "$FQDN" @127.0.0.1 2>/dev/null | grep -v "^;" | grep -v "^$" | awk '{print $NF}' | head -n 1)

    # CLEANUP STEP
    # Unbound's remove command deletes the entire node (both A and AAAA).
    unbound-control -c "$UNBOUND_CONF" local_data_remove "$FQDN" >/dev/null 2>&1
    unbound-control -c "$UNBOUND_CONF" local_data_remove "$IP" >/dev/null 2>&1

    # RESTORE & UPDATE STEP
    
    # A) Apply the CURRENT lease action
    if [ "$ACTION" = "add" ]; then
        unbound-control -c "$UNBOUND_CONF" local_data "$FQDN IN $THIS_TYPE $IP" >/dev/null 2>&1
        unbound-control -c "$UNBOUND_CONF" local_data "$IP PTR $FQDN" >/dev/null 2>&1
        log info "Added $THIS_TYPE for $FQDN ($IP)"
    elif [ "$ACTION" = "remove" ]; then
        log info "Removed $THIS_TYPE for $FQDN ($IP)"
    fi

    # B) Restore the PRESERVED record (if it existed)
    if [ -n "$PRESERVED_IP" ]; then
        unbound-control -c "$UNBOUND_CONF" local_data "$FQDN IN $OTHER_TYPE $PRESERVED_IP" >/dev/null 2>&1
        unbound-control -c "$UNBOUND_CONF" local_data "$PRESERVED_IP PTR $FQDN" >/dev/null 2>&1
        log debug "Preserved $OTHER_TYPE for $FQDN ($PRESERVED_IP)"
    fi
}

# DHCPv4 Events
if [ -n "$LEASE4_ADDRESS" ]; then
    HOST="$LEASE4_HOSTNAME"
    [ -z "$HOST" ] && HOST="device-$(echo "$LEASE4_HWADDR" | tr ':' '-')"
    case "$1" in
        leases4_committed|lease4_renew) update_dns_entry "add" "$LEASE4_ADDRESS" "$HOST" "4" ;;
        lease4_release|lease4_expire|lease4_decline) update_dns_entry "remove" "$LEASE4_ADDRESS" "$HOST" "4" ;;
    esac
    exit 0
fi

# DHCPv6 Events
if [ -n "$LEASE6_ADDRESS" ]; then
    HOST="$LEASE6_HOSTNAME"
    [ -z "$HOST" ] && HOST="device-$(echo "$LEASE6_DUID" | tr ':' '-')"
    case "$1" in
        leases6_committed|lease6_renew) update_dns_entry "add" "$LEASE6_ADDRESS" "$HOST" "6" ;;
        lease6_release|lease6_expire|lease6_decline) update_dns_entry "remove" "$LEASE6_ADDRESS" "$HOST" "6" ;;
    esac
    exit 0
fi
exit 0
EOF
chmod 755 "${KEA_SCRIPT_DIR}/kea-unbound-hook.sh"

# --- 2. The Plugin Registration File ---
cat << 'EOF' > "${STAGE_DIR}/usr/local/etc/inc/plugins.inc.d/keaunbound.inc"
<?php
/*
 * Copyright (C) 2026 OPNsense Community
 * All rights reserved.
 */
function keaunbound_configure() { return; }
EOF

# --- 3. The Installation Script ---
cat << 'EOF' > "${BUILD_DIR}/+POST_INSTALL"
#!/bin/sh
mkdir -p /usr/local/share/kea/scripts
chmod 755 /usr/local/share/kea/scripts

# Python Injection
cat << 'PY_SCRIPT' | /usr/local/bin/python3
import os
import shutil

# --- Configuration ---
files = [
    {
        'ctrl': '/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings4.xml',
        'model': '/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml',
        'php': '/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php',
        'socket_id': 'dhcpv4.general.dhcp_socket_type',
        'prefix': 'dhcpv4',
        'cnf_key': 'Dhcp4'
    },
    {
        'ctrl': '/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings6.xml',
        'model': '/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.xml',
        'php': '/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.php',
        'anchor_id': 'dhcpv6.general.fwrules',
        'prefix': 'dhcpv6',
        'cnf_key': 'Dhcp6'
    }
]

def backup_file(filepath):
    if os.path.exists(filepath) and not os.path.exists(filepath + '.bak'):
        shutil.copy2(filepath, filepath + '.bak')
        print(f'Backed up {filepath}')

for fset in files:
    if not os.path.exists(fset['ctrl']): continue

    backup_file(fset['ctrl'])
    backup_file(fset['model'])
    backup_file(fset['php'])
    print(f"Injecting Kea-Unbound configuration for {fset['cnf_key']}...")

    # 1. Modify UI Form
    with open(fset['ctrl'], 'r') as f: lines = f.readlines()
    if not any('registerDynamicLeases' in line for line in lines):
        with open(fset['ctrl'], 'w') as f:
            found_anchor = False
            inserted = False
            anchor = fset.get('socket_id', fset.get('anchor_id'))
            for line in lines:
                f.write(line)
                if anchor in line: found_anchor = True
                if found_anchor and '</field>' in line and not inserted:
                    f.write('    <field>\n')
                    f.write(f'        <id>{fset["prefix"]}.general.registerDynamicLeases</id>\n')
                    f.write('        <label>Register Leases in Unbound (via os-kea-unbound)</label>\n')
                    f.write('        <type>checkbox</type>\n')
                    f.write('        <help>Enable DNS registration for dynamic DHCP leases (Plugin Feature).</help>\n')
                    f.write('    </field>\n')
                    inserted = True
                    found_anchor = False

    # 2. Modify Model XML
    with open(fset['model'], 'r') as f: content = f.read()
    if 'registerDynamicLeases' not in content:
        with open(fset['model'], 'w') as f:
            for line in content.splitlines(True):
                if '</general>' in line:
                     f.write('            <registerDynamicLeases type="BooleanField">\n')
                     f.write('                <Default>0</Default>\n')
                     f.write('                <Required>N</Required>\n')
                     f.write('            </registerDynamicLeases>\n')
                f.write(line)

    # 3. Modify PHP Logic
    with open(fset['php'], 'r') as f: content = f.read()
    if 'kea-unbound-hook.sh' not in content:
        with open(fset['php'], 'w') as f:
            for line in content.splitlines(True):
                if 'File::file_put_contents' in line:
                    cnf = fset['cnf_key']
                    f.write(f"        if ((string)$this->general->registerDynamicLeases === '1') {{\n")
                    f.write(f"            if (!isset($cnf['{cnf}']['hooks-libraries'])) {{\n")
                    f.write(f"                $cnf['{cnf}']['hooks-libraries'] = [];\n")
                    f.write( "            }\n")
                    f.write(f"            $cnf['{cnf}']['hooks-libraries'][] = [\n")
                    f.write( "                'library' => '/usr/local/lib/kea/hooks/libdhcp_run_script.so',\n")
                    f.write( "                'parameters' => [\n")
                    f.write( "                    'name' => '/usr/local/share/kea/scripts/kea-unbound-hook.sh',\n")
                    f.write( "                    'sync' => false\n")
                    f.write( "                ]\n")
                    f.write( "            ];\n")
                    f.write( "        }\n")
                f.write(line)
PY_SCRIPT

# Ensure script is executable
chmod 755 /usr/local/share/kea/scripts/kea-unbound-hook.sh
# Ensure log file exists and is writable (creates if missing)
touch /var/log/kea-unbound.log
chmod 644 /var/log/kea-unbound.log

service configd restart
echo "Plugin installed. Please go to Services > Kea DHCP > Settings."
EOF
chmod +x "${BUILD_DIR}/+POST_INSTALL"

# --- 4. The Deinstall Script ---
cat << 'EOF' > "${BUILD_DIR}/+PRE_DEINSTALL"
#!/bin/sh
restore() { [ -f "$1.bak" ] && mv "$1.bak" "$1"; }
restore "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings4.xml"
restore "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml"
restore "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php"
restore "/usr/local/opnsense/mvc/app/controllers/OPNsense/Kea/forms/generalSettings6.xml"
restore "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.xml"
restore "/usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.php"
service configd restart
EOF
chmod +x "${BUILD_DIR}/+PRE_DEINSTALL"

# --- 5. The Manifest ---
cat << EOF > "${BUILD_DIR}/+MANIFEST"
name: ${PLUGIN_NAME}
version: "${VERSION}"
origin: opnsense/${PLUGIN_NAME}
comment: Kea DHCP to Unbound DNS dynamic registration
desc: Integrates Kea DHCPv4/v6 with Unbound DNS using Hooks
maintainer: james@jmuk.net 
www: https://github.com/JameZUK/os-kea-unbound 
prefix: /
categories: [sysutils]
licenselogic: single
licenses: [BSD2CLAUSE]
EOF

# --- 6. The Packing List ---
echo ">>> Generating Packing List (plist)..."
cat << EOF > "${BUILD_DIR}/plist"
/usr/local/share/kea/scripts/kea-unbound-hook.sh
/usr/local/etc/inc/plugins.inc.d/keaunbound.inc
EOF

echo ">>> Building Package..."
pkg create -m "${BUILD_DIR}" -r "${STAGE_DIR}" -p "${BUILD_DIR}/plist" -o .

echo "--------------------------------------------------------"
echo " Build Complete!"
echo " 1. REMOVE OLD: pkg delete os-kea-unbound"
echo " 2. INSTALL:    pkg add ./${PLUGIN_NAME}-${VERSION}.pkg"
echo " 3. LOGS:       tail -f /var/log/kea-unbound.log"
echo "--------------------------------------------------------"
