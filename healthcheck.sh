#!/bin/sh
echo "=========================================================="
echo "    os-kea-unbound Health Check (v3.4.0)"
echo "=========================================================="

# 1. Check UI/Model Patch Status
echo -n "[1/5] Checking OPNsense MVC Patches... "
V4_MODEL=$(grep "registerDynamicLeases" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml)
V4_PHP=$(grep "kea-unbound-hook.sh" /usr/local/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php)
if [ -n "$V4_MODEL" ] && [ -n "$V4_PHP" ]; then echo "OK"; else echo "FAILED"; fi

# 2. Check Active Kea Config (Improved Regex for JSON escapes)
echo -n "[2/5] Checking Active Kea Config... "
if grep -q "kea-unbound-hook.sh" /usr/local/etc/kea/kea-dhcp4.conf; then
    echo "OK"
else
    echo "FAILED (Check Services > Kea DHCP > Settings)"
fi

# 3. Check Filesystem
echo -n "[3/5] Checking Filesystem... "
[ -x "/usr/local/share/kea/scripts/kea-unbound-hook.sh" ] && echo "OK" || echo "FAILED"

# 4. Check Log Rotation
echo -n "[4/5] Checking Log Rotation... "
[ -f "/usr/local/etc/newsyslog.conf.d/keaunbound.conf" ] && echo "OK" || echo "FAILED"

# 5. Check Unbound Connectivity
echo -n "[5/5] Checking Unbound Control... "
unbound-control -c /var/unbound/unbound.conf status >/dev/null 2>&1 && echo "OK" || echo "FAILED"

echo "=========================================================="
echo "Recent Leases (last 5):"
tail -n 5 /var/log/kea-unbound.log
echo "=========================================================="
