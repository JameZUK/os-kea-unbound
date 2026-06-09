from lib import tsig


def test_algorithm_name_supported():
    assert tsig.algorithm_name("hmac-sha256") == "hmac-sha256"
    assert tsig.algorithm_name("HMAC-SHA512") == "hmac-sha512"
    assert tsig.algorithm_name("hmac-sha1") == "hmac-sha1"


def test_algorithm_name_drops_weak_and_unknown():
    # md5 is NOT honoured — it (and any unknown) falls back to the strong default,
    # which must match the listener's verification default so D2 + listener agree.
    assert tsig.algorithm_name("hmac-md5") == "hmac-sha256"
    assert tsig.algorithm_name("hmac-sha224") == "hmac-sha256"
    assert tsig.algorithm_name("") == "hmac-sha256"
    assert tsig.algorithm_name(None) == "hmac-sha256"


def test_algo_matches():
    # the listener's algorithm pin (accept == True)
    assert tsig.algo_matches("hmac-sha256.", "hmac-sha256")        # trailing dot + case
    assert tsig.algo_matches("HMAC-SHA256", "hmac-sha256")
    assert not tsig.algo_matches("hmac-sha1.", "hmac-sha256")      # downgrade rejected
    assert not tsig.algo_matches("hmac-md5.sig-alg.reg.int.", "hmac-sha256")
    # empty/unknown INBOUND algorithm -> reject (fail closed); empty configured
    # want -> accept (want is always set in practice)
    assert not tsig.algo_matches("", "hmac-sha256")
    assert not tsig.algo_matches(None, "hmac-sha256")
    assert tsig.algo_matches("hmac-sha256", "")


def test_build_keyring_adds_trailing_dot():
    try:
        import dns.tsigkeyring  # noqa: F401
    except ImportError:
        return  # dnspython absent (off-box CI); build_keyring is covered on-box
    kr = tsig.build_keyring("keaunbound", "YWJjZA==")
    # dnspython keys the ring by absolute name
    assert any(str(k).rstrip(".") == "keaunbound" for k in kr)
