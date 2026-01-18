# os-kea-unbound

**Native OPNsense Plugin: Kea DHCP to Unbound DNS Registration**

This plugin bridges the gap between the Kea DHCP server (IPv4 & IPv6) and Unbound DNS on OPNsense. It automatically registers hostnames for DHCP clients into the Unbound DNS subsystem, restoring dynamic DNS functionality with robust dual-stack support.

## Features

* **Smart Update Logic:** Intelligently handles Dual-Stack environments. It preserves existing IPv4 records when adding IPv6 (and vice versa), eliminating race conditions.
* **Partial Cleanup:** Safely removes expired leases for one IP version without deleting the active record for the other.
* **Native UI Integration:** Adds a simple configuration checkbox directly into the Kea DHCPv4 and DHCPv6 settings pages.
* **Dedicated Logging:** Writes detailed, timestamped activity logs to `/var/log/kea-unbound.log` for clear visibility and troubleshooting.
* **Smart Hostnames:** Automatically generates hostnames from MAC addresses or DUIDs if the client device does not provide one.
* **Non-Destructive:** Uses OPNsense's native hook system to inject configuration safely without modifying core system files.

<img width="1804" height="997" alt="Screenshot" src="https://github.com/user-attachments/assets/0bbc7bc4-bd0f-469d-aa2b-1108f91b44f6" />

## Prerequisites

Before installing, ensure the following services are enabled in OPNsense:

1.  **Kea DHCPv4** and/or **Kea DHCPv6**.
2.  **Unbound DNS**.
3.  **Kea Control Agent:** This service **must be enabled** for the plugin to function correctly.
    * Navigate to **Services > Kea DHCP > Control Agent**.
    * Enable the service and click **Save**.
    * Start/Restart the service.

## Installation

### Option 1: Direct Installation (Recommended)
You can install the pre-compiled package directly via the OPNsense shell (SSH).

1.  Log in to your OPNsense router via SSH.
2.  Run the following command (replace URL with the latest release):

```sh
pkg add https://github.com/JameZUK/os-kea-unbound/releases/download/25.7.11_1A/os-kea-unbound-3.2.pkg
```

*Note: You may see a "misconfigured" warning next to the plugin in the OPNsense web interface. This is cosmetic and expected when installing packages manually outside of a signed repository.*

### Option 2: Build from Source
If you prefer to build the package yourself:

1.  Download the `build_package.sh` script from this repository.
2.  Upload the script to your OPNsense router.
3.  Run the following commands:

```sh
chmod +x build_package.sh
./build_package.sh
pkg add ./os-kea-unbound-3.2.pkg
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

## Verification

Unlike legacy scripts that wrote to a text file, this plugin injects records directly into Unbound's memory for immediate availability.

### 1. Check the Log File
The plugin writes to its own dedicated log file. Watch it to see real-time updates:

```sh
tail -f /var/log/kea-unbound.log
```
*Output Example:*
```text
2026-01-18 12:51:24 [info] Added A for test-device.int.domain.co.uk (192.168.1.50)
2026-01-18 12:51:24 [debug] Preserved A for test-device.int.domain.co.uk (192.168.1.50)
2026-01-18 12:51:24 [info] Added AAAA for test-device.int.domain.co.uk (2001:db8::100)
```

### 2. Query Unbound Directly
Check if a specific host is resolvable in the live system:

```sh
unbound-control -c /var/unbound/unbound.conf list_local_data | grep "my-device"
```

## Uninstallation

To remove the plugin and revert all changes:

```sh
pkg delete os-kea-unbound
```

This will automatically remove the hook script, the log file, and restore the original Kea configuration files. You should restart the Kea services after uninstallation.

## License

BSD 2-Clause License. See the `LICENSE` file for details.

## Acknowledgements

Based on the discussion and concepts in [OPNsense Core Issue #7475](https://github.com/opnsense/core/issues/7475).
