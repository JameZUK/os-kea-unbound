#!/bin/sh
echo "=========================================================="
echo "    os-kea-unbound Health Check (v3.4.0)"
echo "=========================================================="

# 1. Check UI/Model Patch Status (DHCPv4)
echo -n "[1/10] Checking OPNsense MVC Patches (DHCPv4)... "
V4_MODEL=$(grep "registerDynamicLeases" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml 2>/dev/null)
V4_PHP=$(grep "kea-unbound-hook.sh" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php 2>/dev/null)
if [ -n "$V4_MODEL" ] && [ -n "$V4_PHP" ]; then echo "OK"; else echo "FAILED"; fi

# 2. Check UI/Model Patch Status (DHCPv6)
echo -n "[2/10] Checking OPNsense MVC Patches (DHCPv6)... "
V6_MODEL=$(grep "registerDynamicLeases" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.xml 2>/dev/null)
V6_PHP=$(grep "kea-unbound-hook.sh" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.php 2>/dev/null)
if [ -n "$V6_MODEL" ] && [ -n "$V6_PHP" ]; then echo "OK"; else echo "FAILED"; fi

# 3. Check Active Kea Config
echo -n "[3/10] Checking Active Kea Config... "
V4_CONF=$(grep -q "kea-unbound-hook.sh" /usr/local/etc/kea/kea-dhcp4.conf 2>/dev/null && echo "v4")
V6_CONF=$(grep -q "kea-unbound-hook.sh" /usr/local/etc/kea/kea-dhcp6.conf 2>/dev/null && echo "v6")
if [ -n "$V4_CONF" ] || [ -n "$V6_CONF" ]; then
    echo "OK (${V4_CONF:+DHCPv4 }${V6_CONF:+DHCPv6})"
else
    echo "FAILED (Check Services > Kea DHCP > Settings)"
fi

# 4. Check Hook Script
echo -n "[4/10] Checking Hook Script... "
[ -x "/usr/local/share/kea/scripts/kea-unbound-hook.sh" ] && echo "OK" || echo "FAILED"

# 5. Check Plugin Registration
echo -n "[5/10] Checking Plugin Registration... "
[ -f "/usr/local/etc/inc/plugins.inc.d/keaunbound.inc" ] && echo "OK" || echo "FAILED"

# 6. Check Persistence Hooks
echo -n "[6/10] Checking Persistence Hooks... "
UPDATE_OK=false; BOOT_OK=false
[ -x "/usr/local/etc/rc.syshook.d/update/50-keaunbound-repair" ] && UPDATE_OK=true
[ -x "/usr/local/etc/rc.syshook.d/early/50-keaunbound-repair" ] && BOOT_OK=true
if $UPDATE_OK && $BOOT_OK; then echo "OK (update + boot)"
elif $UPDATE_OK; then echo "PARTIAL (update only, missing boot hook)"
elif $BOOT_OK; then echo "PARTIAL (boot only, missing update hook)"
else echo "FAILED"; fi

# 7. Check Log Rotation
echo -n "[7/10] Checking Log Rotation... "
[ -f "/usr/local/etc/newsyslog.conf.d/keaunbound.conf" ] && echo "OK" || echo "FAILED"

# 8. Check Unbound Connectivity
echo -n "[8/10] Checking Unbound Control... "
unbound-control -c /var/unbound/unbound.conf status >/dev/null 2>&1 && echo "OK" || echo "FAILED"

# 9. Check Python3 (required for IPv6 PTR records)
echo -n "[9/10] Checking Python3 (IPv6 PTR)... "
if /usr/local/bin/python3 -c "import ipaddress" 2>/dev/null; then
    echo "OK"
else
    echo "FAILED (python3 with ipaddress module required for IPv6 PTR)"
fi

# 10. Check drill command (required for dual-stack preservation)
echo -n "[10/10] Checking drill (DNS lookup)... "
if command -v drill >/dev/null 2>&1; then echo "OK"
else echo "FAILED (drill required for dual-stack record preservation)"; fi

echo "=========================================================="
echo "Recent Leases (last 5):"
tail -n 5 /var/log/kea-unbound.log 2>/dev/null
echo "=========================================================="
