# os-kea-unbound

**Native OPNsense Plugin: Kea DHCP to Unbound DNS Registration**

This plugin bridges the gap between the Kea DHCP server (IPv4 & IPv6) and Unbound DNS on OPNsense. It automatically registers hostnames for DHCP clients into the Unbound DNS subsystem, restoring dynamic DNS functionality with robust dual-stack support.

## Features

* **Smart Update Logic:** Intelligently handles dual-stack environments. It preserves existing IPv4 records when adding IPv6 (and vice versa).
* **Concurrency Safe:** Uses `lockf(1)` serialization to prevent race conditions when concurrent DHCPv4 and DHCPv6 lease events fire for the same host.
* **Automatic PTR Generation:** Generates reverse DNS (PTR) records for both IPv4 (`in-addr.arpa`) and IPv6 (`ip6.arpa`), with graceful fallback if the PTR computation fails.
* **Hostname Normalization:** Lowercases hostnames, strips domain suffixes from FQDN inputs, and removes invalid characters to ensure clean DNS entries.
* **Smart Hostnames:** Automatically generates hostnames from MAC addresses (IPv4) or DUIDs (IPv6) if the client device does not provide one.
* **Persistence & Repair:** Includes `rc.syshook.d` scripts to ensure patches survive OPNsense firmware updates and system reboots.
* **Dedicated Logging:** Writes detailed, timestamped activity logs to `/var/log/kea-unbound.log` with automatic rotation via `newsyslog`.
* **Non-Destructive:** Uses OPNsense's native hook system to inject configuration safely without modifying core system files.

<img width="1804" height="997" alt="Screenshot" src="https://github.com/user-attachments/assets/0bbc7bc4-bd0f-469d-aa2b-1108f91b44f6" />

## Prerequisites

Before installing, ensure the following services are enabled in OPNsense:

1.  **Kea DHCPv4** and/or **Kea DHCPv6**.
2.  **Unbound DNS**.
3.  **Python3** (pre-installed on OPNsense) — required for IPv6 reverse PTR generation.
4.  **Kea Control Agent:** This service **must be enabled** for the plugin to function correctly.
    * Navigate to **Services > Kea DHCP > Control Agent**.
    * Enable the service and click **Save**.
    * Start/Restart the service.

## Installation

### Option 1: Direct Installation (Recommended)
You can install the pre-compiled package directly via the OPNsense shell (SSH).

1.  Log in to your OPNsense router via SSH.
2.  Run the following command:


```sh
pkg add https://github.com/JameZUK/os-kea-unbound/releases/download/25.7.11_Fixes/os-kea-unbound-3.3.9.pkg
```

*Note: You may see a "misconfigured" warning next to the plugin in the OPNsense web interface. This is cosmetic and expected when installing packages manually outside of a signed repository.*

### Option 2: Build from Source
If you prefer to build the package yourself:

1.  Download the `build_plugin.sh` script from this repository.
2.  Upload the script to your OPNsense router.
3.  Run the following commands:

```sh
chmod +x build_plugin.sh
./build_plugin.sh
pkg add ./os-kea-unbound-3.3.9.pkg
```

## Configuration

Once installed, you must enable the registration feature in the Kea settings.

1.  **IPv4 Configuration:**
    * Navigate to **Services > Kea DHCP > Kea DHCPv4 > Settings**.
    * Locate the **General Settings** section.
    * Tick the checkbox: **Register Leases in Unbound (via os-kea-unbound)**.
    * Click **Save**.

2.  **IPv6 Configuration:**
    * Navigate to **Services > Kea DHCP > Kea DHCPv6 > Settings**.
    * Locate the **General Settings** section.
    * Tick the checkbox: **Register Leases in Unbound (via os-kea-unbound)**.
    * Click **Save**.

3.  **Apply Changes:**
    * Restart **Kea DHCPv4**.
    * Restart **Kea DHCPv6**.

The plugin will immediately begin processing lease events.

## Upgrading

To prevent configuration conflicts or service crashes during an upgrade, follow this "Clean Upgrade" procedure.

1.  **Disable Hooks:**
    * Navigate to **Services > Kea DHCP > Settings**.
    * **Uncheck** the "Register Leases in Unbound" box and click **Save**.
    * *This safely detaches the hook from Kea configuration files.*

2.  **Replace Package:**
    * Log in via SSH and run:
    ```sh
    pkg delete os-kea-unbound
    pkg add ./os-kea-unbound-3.3.9.pkg
    ```

3.  **Re-Enable Hooks:**
    * Return to **Services > Kea DHCP > Settings**.
    * **Check** the "Register Leases in Unbound" box and click **Save**.
    * Restart the Kea services.

## Troubleshooting & Recovery

If Kea fails to start after an upgrade (e.g., due to a lingering invalid path), use these recovery methods.

### 1. Manual Bypass (CLI)
If the web interface is inaccessible or Kea is crashing, run these commands via SSH to surgically remove the hook configuration. This will allow Kea to start without the plugin.

```sh
sed -i '' '/"hooks-libraries"/,/\]/d' /usr/local/etc/kea/kea-dhcp4.conf
sed -i '' '/"hooks-libraries"/,/\]/d' /usr/local/etc/kea/kea-dhcp6.conf
service kea-dhcp4 restart
service kea-dhcp6 restart
```

### 2. Restore Configuration
If the OPNsense configuration is corrupted, you can restore a previous backup from the console:
1.  Access the console (SSH or physical screen).
2.  Select **Option 13** (Restore a backup).
3.  Select a configuration timestamped prior to the failed upgrade.

### 3. Factory Reset
In the event of a total lockout where no other method works:
1.  Access the console.
2.  Select **Option 4** (Reset to factory defaults).
3.  Once the system reboots (default IP: 192.168.1.1), restore your configuration via the Web GUI.

## Verification

### 1. Check the Log File
Watch the dedicated log file for real-time updates:

```sh
tail -f /var/log/kea-unbound.log
```
*Output Example:*
```text
2026-01-19 18:42:05 [info] Added AAAA for client-device.example.com (2001:db8::1001) [PTR: 1.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa]
2026-01-19 18:42:08 [info] Added A for smart-device.example.com (192.168.1.10) [PTR: 10.1.168.192.in-addr.arpa]
```

### 2. Run Health Check
A diagnostic script is provided to validate the installation. It performs 7 checks:

1. OPNsense MVC patches (DHCPv4)
2. OPNsense MVC patches (DHCPv6)
3. Active Kea configuration
4. Filesystem (hook script exists and is executable)
5. Log rotation configuration
6. Unbound connectivity
7. Python3 availability (required for IPv6 PTR)

```sh
./healthcheck.sh
```

### 3. Run the Test Suite
A comprehensive regression test suite (`test_hook.sh`) validates the hook script against a live Unbound instance. It covers:

* IPv4 and IPv6 single-stack lifecycles (add/release)
* Dual-stack preservation in both orders (v4->v6 and v6->v4)
* Partial removal (removing one stack preserves the other)
* Hostname normalization (uppercase, FQDN input, special characters)
* MAC address fallback when hostname is empty

```sh
./test_hook.sh
```

### 4. Query Unbound Directly
Check if a host is resolvable in the live system:

```sh
unbound-control -c /var/unbound/unbound.conf list_local_data | grep "smart-device"
```

## Uninstallation

To remove the plugin and revert all changes:

```sh
pkg delete os-kea-unbound
```

This will automatically remove the hook script, rotation configuration, and restore the original Kea configuration files. You should restart the Kea services after uninstallation.

## License

BSD 2-Clause License. See the `LICENSE` file for details.

## Acknowledgements

Based on the discussion and concepts in [OPNsense Core Issue #7475](https://github.com/opnsense/core/issues/7475).
