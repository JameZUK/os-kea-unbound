#!/bin/sh

# 1. Define Variables
PLUGIN_NAME="os-kea-unbound"
VERSION="2.6" # Fix: Garbage Collection & Regex
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

# --- 1. The Clean Hook Script (v2.6) ---
cat << 'EOF' > "${KEA_SCRIPT_DIR}/kea-unbound-hook.sh"
#!/bin/sh
# Kea DHCPv4 & DHCPv6 Unbound DNS Hook Script (v2.6)

LOG_TAG="kea-unbound-hook"
LEASES_FILE="/var/unbound/dhcpleases.conf"
TMP_FILE="$LEASES_FILE.tmp"
HOST_ENTRIES="/var/unbound/host_entries.conf"
UNBOUND_CONF="/var/unbound/unbound.conf"
KEA_CTRL_CONF="/usr/local/etc/kea/kea-ctrl-agent.conf"

log() {
  LEVEL="$1"
  MSG="$2"
  if [ "$LEVEL" = "debug" ]; then
    logger -t "kea-hook" -p local4.debug "$LOG_TAG: $MSG" 2>/dev/null || echo "$LOG_TAG: $MSG" >&2
  else
    logger -t "kea-hook" -p local4.info "$LOG_TAG: $MSG" 2>/dev/null || echo "$LOG_TAG: $MSG" >&2
  fi
}

get_ca_url() {
  jq -r '"http://" + ."Control-agent"."http-host" + ":" + (."Control-agent"."http-port"|tostring)' "$KEA_CTRL_CONF" 2>/dev/null
}

normalize_hostname() {
  echo "$1" | tr 'A-Z' 'a-z' | sed 's/\..*//' | sed 's/[^a-z0-9-]//g'
}

get_ip_ver() {
  case "$1" in
    *:*) echo "6" ;;
    *)   echo "4" ;;
  esac
}

get_system_domain() {
  D=$(hostname -d 2>/dev/null)
  [ -z "$D" ] && echo "home.arpa" || echo "$D"
}

get_domain_for_ip() {
  IP="$1"
  VER=$(get_ip_ver "$IP")
  SYSTEM_DOMAIN=$(get_system_domain)

  CA_URL=$(get_ca_url)
  [ -z "$CA_URL" ] && { echo "$SYSTEM_DOMAIN"; return; } 
  
  CMD="lease4-get"
  SVC="dhcp4"
  if [ "$VER" = "6" ]; then
    CMD="lease6-get"
    SVC="dhcp6"
  fi

  OUTPUT=$(curl -s -X POST "$CA_URL" -H 'Content-Type: application/json' \
    -d '{"command": "'"$CMD"'", "arguments": {"ip-address": "'"$IP"'"}, "service": ["'"$SVC"'"]}')
  
  SUBNET_ID=$(echo "$OUTPUT" | jq -r '.[0].arguments["subnet-id"] // empty')
  
  [ -z "$SUBNET_ID" ] && { echo "$SYSTEM_DOMAIN"; return; }

  CONFIG=$(curl -s -X POST "$CA_URL" -H 'Content-Type: application/json' \
    -d '{"command": "config-get", "service": ["'"$SVC"'"]}')
  
  if [ "$VER" = "6" ]; then
     DOMAIN=$(echo "$CONFIG" | jq -r --arg id "$SUBNET_ID" '.[] | .arguments.Dhcp6.subnet6[] | select(.id == ($id|tonumber)) | ."option-data"[]? | select(.name == "domain-search") | .data')
  else
     DOMAIN=$(echo "$CONFIG" | jq -r --arg id "$SUBNET_ID" '.[] | .arguments.Dhcp4.subnet4[] | select(.id == ($id|tonumber)) | ."option-data"[]? | select(.name == "domain-name") | .data')
  fi

  DOMAIN=$(echo "$DOMAIN" | tr -d '\n\r' | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9.-]//g')
  
  if [ -n "$DOMAIN" ]; then
      echo "$DOMAIN"
  else
      echo "$SYSTEM_DOMAIN"
  fi
}

add_dns_entry() {
  IP="$1"
  NAME="$2"
  if [ -n "$3" ]; then
      DOMAIN="$3"
  else
      DOMAIN=$(get_domain_for_ip "$IP")
  fi

  [ -z "$NAME" ] && return
  NAME=$(normalize_hostname "$NAME")
  [ -z "$NAME" ] && return

  FQDN="$NAME.$DOMAIN"
  VER=$(get_ip_ver "$IP")
  REC_TYPE="A"
  [ "$VER" = "6" ] && REC_TYPE="AAAA"

  # Fix: Regex now matches IP followed by quote OR space to handle both format types
  sed -i '' "/$IP[\" ]/d" "$TMP_FILE" 2>/dev/null
  sed -i '' "/$FQDN IN $REC_TYPE/d" "$TMP_FILE" 2>/dev/null

  echo "local-data: \"$FQDN IN $REC_TYPE $IP\"" >> "$TMP_FILE"
  echo "local-data-ptr: \"$IP $FQDN\"" >> "$TMP_FILE"
  
  unbound-control -c "$UNBOUND_CONF" local_data_remove "$FQDN" >/dev/null 2>&1
  unbound-control -c "$UNBOUND_CONF" local_data "$FQDN IN $REC_TYPE $IP" >/dev/null 2>&1
  
  unbound-control -c "$UNBOUND_CONF" local_data_remove "$IP" >/dev/null 2>&1
  unbound-control -c "$UNBOUND_CONF" local_data "$IP PTR $FQDN" >/dev/null 2>&1

  log debug "add_dns_entry: Added $REC_TYPE $FQDN -> $IP"
}

remove_dns_entry() {
  IP="$1"
  [ -z "$IP" ] && return
  log debug "remove_dns_entry: Removing $IP"
  unbound-control -c "$UNBOUND_CONF" local_data_remove "$IP" >/dev/null 2>&1
  sed -i '' "/$IP[\" ]/d" "$LEASES_FILE" 2>/dev/null
}

sync_all_leases() {
    log info "sync_all_leases: Starting bulk sync..."
    CA_URL=$(get_ca_url)
    [ -z "$CA_URL" ] && { log error "sync_all_leases: CA URL missing"; return; }

    # Fix: Start with an EMPTY file (truncate). 
    # This acts as garbage collection for old/stale/duplicate entries.
    > "$TMP_FILE"

    LEASES4=$(curl -s -X POST "$CA_URL" -H 'Content-Type: application/json' \
      -d '{"command": "lease4-get-all", "service": ["dhcp4"]}' | jq -c '.[0].arguments.leases[]?')
    
    if [ -n "$LEASES4" ] && [ "$LEASES4" != "null" ]; then
        echo "$LEASES4" | jq -c '.' | while read -r lease; do
            IP=$(echo "$lease" | jq -r '."ip-address"')
            HOST=$(echo "$lease" | jq -r '."hostname"')
            MAC=$(echo "$lease" | jq -r '."hw-address"')
            
            [ -z "$HOST" ] || [ "$HOST" = "null" ] && HOST="device-$(echo "$MAC" | tr ':' '-')"
            add_dns_entry "$IP" "$HOST"
        done
    fi

    LEASES6=$(curl -s -X POST "$CA_URL" -H 'Content-Type: application/json' \
      -d '{"command": "lease6-get-all", "service": ["dhcp6"]}' | jq -c '.[0].arguments.leases[]?')
    
    if [ -n "$LEASES6" ] && [ "$LEASES6" != "null" ]; then
        echo "$LEASES6" | jq -c '.' | while read -r lease; do
            IP=$(echo "$lease" | jq -r '."ip-address"')
            HOST=$(echo "$lease" | jq -r '."hostname"')
            DUID=$(echo "$lease" | jq -r '."duid"')
            
            [ -z "$HOST" ] || [ "$HOST" = "null" ] && HOST="device-$(echo "$DUID" | tr ':' '-')"
            add_dns_entry "$IP" "$HOST"
        done
    fi

    sort -u "$TMP_FILE" > "$LEASES_FILE"
    rm -f "$TMP_FILE"
    service unbound reload >/dev/null 2>&1
    log info "sync_all_leases: Bulk sync complete."
}

if [ -n "$LEASE4_ADDRESS" ]; then
    case "$1" in
        leases4_committed|lease4_renew)
            HOST="$LEASE4_HOSTNAME"
            [ -z "$HOST" ] && HOST="device-$(echo "$LEASE4_HWADDR" | tr ':' '-')"
            add_dns_entry "$LEASE4_ADDRESS" "$HOST"
            exit 0 ;;
        lease4_release|lease4_expire|lease4_decline)
            remove_dns_entry "$LEASE4_ADDRESS"
            exit 0 ;;
    esac
fi

if [ -n "$LEASE6_ADDRESS" ]; then
    case "$1" in
        leases6_committed|lease6_renew)
            HOST="$LEASE6_HOSTNAME"
            [ -z "$HOST" ] && HOST="device-$(echo "$LEASE6_DUID" | tr ':' '-')"
            add_dns_entry "$LEASE6_ADDRESS" "$HOST"
            exit 0 ;;
        lease6_release|lease6_expire|lease6_decline)
            remove_dns_entry "$LEASE6_ADDRESS"
            exit 0 ;;
    esac
fi

if [ "$1" = "sync" ]; then
    sync_all_leases
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

function keaunbound_configure()
{
    return [
        'bootup' => ['keaunbound_bootup_sync'],
    ];
}

function keaunbound_bootup_sync()
{
    mwexec_bg('/usr/local/share/kea/scripts/kea-unbound-hook.sh sync');
}
EOF

# --- 3. The Installation Script ---
cat << 'EOF' > "${BUILD_DIR}/+POST_INSTALL"
#!/bin/sh

# Ensure the script directory exists and is accessible
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
    if not os.path.exists(fset['ctrl']):
        continue

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
                if anchor in line:
                    found_anchor = True
                
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

# Ensure script is executable and exists
chmod 755 /usr/local/share/kea/scripts/kea-unbound-hook.sh
if [ ! -f /usr/local/share/kea/scripts/kea-unbound-hook.sh ]; then
    echo "ERROR: Hook script missing! Check installation."
    exit 1
fi

# Run initial sync
/usr/local/share/kea/scripts/kea-unbound-hook.sh sync

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

rm -f /var/run/configd_template.cache
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
echo "--------------------------------------------------------"
