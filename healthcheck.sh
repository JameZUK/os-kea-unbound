#!/bin/sh
echo "=========================================================="
echo "    os-kea-unbound Health Check (v3.3.9)"
echo "=========================================================="

# 1. Check UI/Model Patch Status
echo -n "[1/7] Checking OPNsense MVC Patches (DHCPv4)... "
V4_MODEL=$(grep "registerDynamicLeases" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml 2>/dev/null)
V4_PHP=$(grep "kea-unbound-hook.sh" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php 2>/dev/null)
if [ -n "$V4_MODEL" ] && [ -n "$V4_PHP" ]; then echo "OK"; else echo "FAILED"; fi

echo -n "[2/7] Checking OPNsense MVC Patches (DHCPv6)... "
V6_MODEL=$(grep "registerDynamicLeases" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.xml 2>/dev/null)
V6_PHP=$(grep "kea-unbound-hook.sh" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv6.php 2>/dev/null)
if [ -n "$V6_MODEL" ] && [ -n "$V6_PHP" ]; then echo "OK"; else echo "FAILED"; fi

# 2. Check Active Kea Config
echo -n "[3/7] Checking Active Kea Config... "
V4_CONF=$(grep -q "kea-unbound-hook.sh" /usr/local/etc/kea/kea-dhcp4.conf 2>/dev/null && echo "v4")
V6_CONF=$(grep -q "kea-unbound-hook.sh" /usr/local/etc/kea/kea-dhcp6.conf 2>/dev/null && echo "v6")
if [ -n "$V4_CONF" ] || [ -n "$V6_CONF" ]; then
    echo "OK (${V4_CONF:+DHCPv4 }${V6_CONF:+DHCPv6})"
else
    echo "FAILED (Check Services > Kea DHCP > Settings)"
fi

# 3. Check Filesystem
echo -n "[4/7] Checking Filesystem... "
[ -x "/usr/local/share/kea/scripts/kea-unbound-hook.sh" ] && echo "OK" || echo "FAILED"

# 4. Check Log Rotation
echo -n "[5/7] Checking Log Rotation... "
[ -f "/usr/local/etc/newsyslog.conf.d/keaunbound.conf" ] && echo "OK" || echo "FAILED"

# 5. Check Unbound Connectivity
echo -n "[6/7] Checking Unbound Control... "
unbound-control -c /var/unbound/unbound.conf status >/dev/null 2>&1 && echo "OK" || echo "FAILED"

# 6. Check Python3 (required for IPv6 PTR records)
echo -n "[7/7] Checking Python3 (IPv6 PTR)... "
if /usr/local/bin/python3 -c "import ipaddress" 2>/dev/null; then
    echo "OK"
else
    echo "FAILED (python3 with ipaddress module required for IPv6 PTR)"
fi

echo "=========================================================="
echo "Recent Leases (last 5):"
tail -n 5 /var/log/kea-unbound.log 2>/dev/null
echo "=========================================================="
