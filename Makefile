PLUGIN_NAME=		kea-unbound
PLUGIN_VERSION=		0.1
PLUGIN_COMMENT=		Register Kea DHCP leases in Unbound DNS via DDNS (no core-file patching)
PLUGIN_DEPENDS=		py311-dnspython
PLUGIN_MAINTAINER=	james@jmuk.net

# NOTE: PLUGIN_DEPENDS must match the OPNsense base python version. 25.x ships
# python 3.11 (py311-dnspython). Adjust if the target base differs (e.g. py313).

.include "../../Mk/plugins.mk"
