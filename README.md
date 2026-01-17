os-kea-unbound

Native OPNsense Plugin: Kea DHCP to Unbound DNS Registration

This plugin bridges the gap between the Kea DHCP server (v4 & v6) and Unbound DNS on OPNsense. It automatically registers hostnames for DHCP clients into the Unbound DNS subsystem, restoring the dynamic DNS registration functionality previously available in the legacy ISC DHCP server.
Features

    Dual Stack Support: Fully functional for both IPv4 and IPv6 DHCP leases.

    Native UI Integration: Adds a simple configuration checkbox directly into the Kea DHCPv4 and DHCPv6 settings pages.

    Automatic Sync: Performs a bulk synchronisation of existing leases upon installation or boot, ensuring DNS records are immediately populated.

    Smart Hostnames: Automatically generates hostnames from MAC addresses or DUIDs if the client device does not provide one.

    System Domain Fallback: Correctly assigns the system domain (e.g., int.yourdomain.co.uk) to leases, preventing generic home.arpa entries.

    Non-Destructive: Uses OPNsense's native hook system to inject configuration safely without modifying core system files.

Prerequisites

Before installing, ensure the following services are enabled in OPNsense:

    Kea DHCPv4 and/or Kea DHCPv6.

    Unbound DNS.

    Kea Control Agent: This service must be enabled for the plugin to synchronise existing leases.

        Navigate to Services > Kea DHCP > Control Agent.

        Enable the service and click Save.

        Start/Restart the service.

Installation
Option 1: Direct Installation (Recommended)

You can install the pre-compiled package directly via the OPNsense shell (SSH). This method requires no additional tools.

    Log in to your OPNsense router via SSH.

    Run the following command:

Bash

pkg add https://github.com/JameZUK/os-kea-unbound/releases/download/v2.6/os-kea-unbound-2.6.pkg

Note: You may see a "misconfigured" warning next to the plugin in the OPNsense web interface. This is cosmetic and expected when installing packages manually outside of a signed repository.
Option 2: Build from Source

If you prefer to build the package yourself:

    Download the build_plugin.sh script from this repository.

    Upload the script to your OPNsense router.

    Run the following commands:

Bash

chmod +x build_plugin.sh
./build_plugin.sh
pkg add ./os-kea-unbound-2.6.pkg

Configuration

Once installed, you must enable the registration feature in the Kea settings.

    IPv4 Configuration:

        Navigate to Services > Kea DHCP > Kea DHCPv4 > Settings.

        Locate the General Settings section.

        Tick the checkbox: Register Leases in Unbound (via os-kea-unbound).

        Click Save.

    IPv6 Configuration:

        Navigate to Services > Kea DHCP > Kea DHCPv6 > Settings.

        Locate the General Settings section.

        Tick the checkbox: Register Leases in Unbound (via os-kea-unbound).

        Click Save.

    Apply Changes:

        Restart Kea DHCPv4.

        Restart Kea DHCPv6.

The plugin will immediately perform a synchronisation of all active leases.
Verification

To verify that DNS records are being generated correctly, you can inspect the generated configuration file on the router:
Bash

grep "local-data" /var/unbound/dhcpleases.conf

You should see entries for your active DHCP clients, such as:
Plaintext

local-data: "my-device.int.domain.co.uk IN A 192.168.1.50"
local-data: "my-device.int.domain.co.uk IN AAAA 2a11:2646::100"

Uninstallation

To remove the plugin and revert all changes:
Bash

pkg delete os-kea-unbound

This will automatically remove the hook script and restore the original Kea configuration files. You should restart the Kea services after uninstallation.
License

BSD 2-Clause License. See the LICENSE file for details.
