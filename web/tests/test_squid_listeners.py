from services.squid_listeners import listener_is_present, parse_squid_listeners


def test_parser_covers_address_ipv6_https_and_transparent_modes():
    listeners = parse_squid_listeners("""
http_port 127.0.0.1:3128 ssl-bump
http_port [::1]:3129 tproxy
https_port 0.0.0.0:3130 intercept ssl-bump
""")
    assert [
        (item["host"], item["port"], item["mode"], item["response"])
        for item in listeners
    ] == [
        ("127.0.0.1", 3128, "explicit", True),
        ("::1", 3129, "tproxy", False),
        ("0.0.0.0", 3130, "https-intercept", False),  # noqa: S104 - parsed listener fixture.
    ]


def test_bound_address_contract_does_not_accept_wrong_same_port_listener():
    listener = parse_squid_listeners("http_port 127.0.0.2:3128")[0]
    assert not listener_is_present(listener, {("127.0.0.1", 3128)})
    assert listener_is_present(
        listener,
        {("0.0.0.0", 3128)},  # noqa: S104 - listening endpoint fixture.
    )
    assert listener_is_present(listener, {("127.0.0.2", 3128)})


def test_malformed_config_falls_back_consistently():
    assert parse_squid_listeners("http_port nope", fallback_port=4128) == (
        {"host": None, "port": 4128, "mode": "explicit", "response": True},
    )
