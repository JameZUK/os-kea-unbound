PLUGIN_NAME=		kea-unbound
PLUGIN_VERSION=		0.12.1
PLUGIN_COMMENT=		Register Kea DHCP leases in Unbound DNS via DDNS (no core-file patching)
PLUGIN_DEPENDS=		py313-dnspython
PLUGIN_MAINTAINER=	james@jmuk.net

# PLUGIN_DEPENDS matches the OPNsense base python: 26.1 ships python 3.13
# (py313-dnspython), confirmed on the test host.

.include "../../Mk/plugins.mk"
