# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
"""
TSIG helpers. Isolates the dnspython dependency so the rest of lib/ stays
import-clean for off-box unit testing.
"""

# Map our stored algorithm strings to dnspython algorithm names. Only the strong
# HMACs the GUI offers are accepted; hmac-md5 is intentionally not supported.
_ALGO_MAP = {
    "hmac-sha256": "hmac-sha256",
    "hmac-sha512": "hmac-sha512",
    "hmac-sha1": "hmac-sha1",
}


def algorithm_name(algo: str) -> str:
    return _ALGO_MAP.get((algo or "").lower(), "hmac-sha256")


def algo_matches(got, want) -> bool:
    """True if an inbound TSIG algorithm should be ACCEPTED given the configured one.

    Normalises both (drop trailing dot, lowercase) and compares. A verified TSIG
    message always carries an algorithm, so an EMPTY inbound algorithm is rejected
    (fail closed — don't let a missing/odd algorithm bypass the pin). Only an empty
    configured `want` is tolerated (it's always set in practice). Pure +
    dnspython-free so the listener's algorithm pin is unit-testable."""
    w = str(want or "").rstrip(".").lower()
    if not w:
        return True  # nothing configured to pin against
    g = str(got or "").rstrip(".").lower()
    return g == w    # empty/unknown inbound algorithm -> reject


def build_keyring(key_name: str, secret_b64: str):
    """
    Build a dnspython keyring for verifying inbound and signing outbound TSIG.
    Imported lazily so modules that don't need TSIG don't pull in dnspython.
    """
    import dns.tsigkeyring  # noqa: WPS433 (lazy import is intentional)

    name = key_name if key_name.endswith(".") else key_name + "."
    return dns.tsigkeyring.from_text({name: secret_b64})
