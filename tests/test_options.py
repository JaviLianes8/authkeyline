"""The options field follows sshauthopt_parse in OpenSSH's auth-options.c."""

from __future__ import annotations

import pytest
from keyfactory import ed25519_line

from authkeyline import AuthKeyError, KeyOption, parse_line

KEY = ed25519_line()


def options(field: str) -> tuple[KeyOption, ...]:
    return parse_line(f"{field} {KEY}").options


@pytest.mark.parametrize(
    "flag",
    [
        "restrict",
        "cert-authority",
        "port-forwarding",
        "no-port-forwarding",
        "agent-forwarding",
        "no-agent-forwarding",
        "X11-forwarding",
        "no-X11-forwarding",
        "pty",
        "no-pty",
        "user-rc",
        "no-user-rc",
        "touch-required",
        "no-touch-required",
        "verify-required",
        "no-verify-required",
    ],
)
def test_every_sshd_flag_is_accepted(flag: str) -> None:
    assert options(flag) == (KeyOption(flag),)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("no-restrict", "unknown option 'no-restrict'"),
        ("no-cert-authority", "unknown option"),
        ("bogus", "unknown option 'bogus'"),
        ("ptyx", "unknown option"),
        ('pty="1"', "unknown option 'pty'"),
        ('bogus="1"', "unknown option 'bogus'"),
        ("command=oops", "must be in double quotes"),
        ('command="x"y', "unexpected 'y' after option 'command'"),
        ('command="unterminated', "no closing quote"),
        ('="x"', "empty option name"),
        ('"x"', "unexpected"),
        ('command="a",command="b"', "'command' appears more than once"),
        ('from="a",FROM="b"', "'from' appears more than once"),
        ('principals="a",principals="b"', "appears more than once"),
    ],
)
def test_sshd_rejects_these_fields(field: str, message: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(f"{field} {KEY}")
    assert message in str(caught.value)


def test_a_trailing_comma_at_the_end_of_the_field_is_an_error() -> None:
    from authkeyline._options import read_options

    with pytest.raises(AuthKeyError, match="end with a comma"):
        read_options("restrict,")
    with pytest.raises(AuthKeyError, match="end with a comma"):
        read_options(",")


def test_repeatable_options_may_repeat() -> None:
    field = (
        'environment="A=1",environment="A=2",permitopen="h:1",permitopen="h:2",'
        'expiry-time="20300101",expiry-time="20310101"'
    )
    assert len(options(field)) == 6


@pytest.mark.parametrize(
    "value",
    ["FOO=1", "foo_2=", "X=a=b, c", "_=x"],
)
def test_environment_accepts_a_word_name(value: str) -> None:
    assert options(f'environment="{value}"') == (KeyOption("environment", value),)


@pytest.mark.parametrize("value", ["", "noequals", "=x", "A-B=1", "A B=1", ",=bah"])
def test_environment_rejects_other_names(value: str) -> None:
    with pytest.raises(AuthKeyError, match="environment="):
        options(f'environment="{value}"')


@pytest.mark.parametrize(
    "value",
    ["host:22", "192.0.2.1:80", "[::1]:22000", "h:*", "*:65535", "[fe80::1]/8080", "h/1", ":80"],
)
def test_permitopen_accepts_host_and_port(value: str) -> None:
    assert options(f'permitopen="{value}"')[0].value == value


@pytest.mark.parametrize(
    "value",
    ["host", "host:", "h:0", "h:65536", "h:ssh", "[::1", "[::1]", "[::1]x80", "::1:80", "h:1:2"],
)
def test_permitopen_rejects_bad_targets_and_port_names(value: str) -> None:
    with pytest.raises(AuthKeyError, match="permitopen"):
        options(f'permitopen="{value}"')


@pytest.mark.parametrize("value", ["8080", "*", "localhost:8080", "[::1]:22000", "*:*"])
def test_permitlisten_also_takes_a_bare_port(value: str) -> None:
    assert options(f'permitlisten="{value}"')[0].value == value


@pytest.mark.parametrize("value", ["", "x", "0", "70000", "h:"])
def test_permitlisten_rejects_bad_ports(value: str) -> None:
    with pytest.raises(AuthKeyError, match="permitlisten"):
        options(f'permitlisten="{value}"')


def test_permit_host_name_length_is_capped() -> None:
    options(f'permitopen="{"a" * 1024}:1"')
    with pytest.raises(AuthKeyError, match="too long"):
        options(f'permitopen="{"a" * 1025}:1"')


@pytest.mark.parametrize("value", ["0", "1", "any", "ANY", "2147483645"])
def test_tunnel_accepts_numbers_and_any(value: str) -> None:
    assert options(f'tunnel="{value}"')[0].value == value


@pytest.mark.parametrize("value", ["", "blah", "-1", "2147483646", "1.5"])
def test_tunnel_rejects_others(value: str) -> None:
    with pytest.raises(AuthKeyError, match="tunnel="):
        options(f'tunnel="{value}"')


@pytest.mark.parametrize(
    "value",
    ["20301231", "20301231Z", "203012312359", "20301231235960z", "20301231UTC", "20300101utc"],
)
def test_expiry_time_accepts_the_sshd_formats(value: str) -> None:
    assert options(f'expiry-time="{value}"')[0].value == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "soon",
        "2030123",
        "2030-12-31",
        "20301331",
        "20300100",
        "20301232",
        "203012312400",
        "203012312360",
        "20301231235961",
        "Z",
        "2030123100Z",
    ],
)
def test_expiry_time_rejects_others(value: str) -> None:
    with pytest.raises(AuthKeyError, match="expiry-time="):
        options(f'expiry-time="{value}"')


def test_environment_limit_counts_distinct_names() -> None:
    from authkeyline._optrules import ENV_MAX

    repeats = ",".join(f'environment="V{i % 3}=1"' for i in range(ENV_MAX + 5))
    assert len(options(repeats)) == ENV_MAX + 5
    allowed = ",".join(f'environment="V{i}=1"' for i in range(ENV_MAX + 1))
    assert len(options(allowed + ",no-pty")) == ENV_MAX + 2
    with pytest.raises(AuthKeyError, match="too many environment"):
        options(allowed + ',environment="V0=2"')


def test_permit_limit() -> None:
    from authkeyline._optrules import PERMIT_MAX

    allowed = ",".join('permitopen="h:1"' for _ in range(PERMIT_MAX + 1))
    assert len(options(allowed + ',permitlisten="1"')) == PERMIT_MAX + 2
    with pytest.raises(AuthKeyError, match="too many permitopen"):
        options(allowed + ',permitopen="h:2"')


def test_quoted_values_may_hold_spaces_tabs_commas_and_quotes() -> None:
    (option,) = options('command="a\tb, \\"c\\" d"')
    assert option.value == 'a\tb, "c" d'
