"""
© https://github.com/YouFoundTheDev | 2026
spill.py
"""

import re
from collections.abc import Iterable, Sequence
from typing import Final
from urllib.parse import urlsplit

from airlock.codec.spectrum import alnum_only, spectrum
from airlock.ruling import Alert, Weight
from airlock.settings import (
    CHECK_SPILL,
    LIMITS,
    PROTOCOL_RELATIVE,
    RULE_HOST_DENIED,
    RULE_REPLY_TOO_LARGE,
    RULE_SECRET_SPILL,
    SUBDOMAIN_MARKER,
    URL_PATTERN,
    URL_SCHEME,
)


_URL: Final = re.compile(URL_PATTERN)


def host_of(candidate: str) -> str:
    """
    The hostname a URL points at, treating a protocol-relative form as
    the https URL it becomes
    """
    if candidate.startswith(PROTOCOL_RELATIVE):
        candidate = f"{URL_SCHEME}{candidate}"
    return urlsplit(candidate).hostname or ""


class SpillCheck:
    """
    The last boundary, where a registered secret must not leave in any
    encoding and an unlisted host must not be contacted
    """

    name = CHECK_SPILL

    def __init__(
        self,
        secrets: Sequence[str] = (),
        hosts: Sequence[str] = (),
    ) -> None:
        self.secrets = tuple(
            secret for secret in secrets
            if len(alnum_only(secret)) >= LIMITS.min_secret_length
        )
        self.rejected = tuple(
            secret for secret in secrets
            if len(alnum_only(secret)) < LIMITS.min_secret_length
        )
        self.hosts = tuple(host.lower() for host in hosts)

    def _allows(self, host: str) -> bool:
        for allowed in self.hosts:
            if allowed.startswith(SUBDOMAIN_MARKER):
                if host == allowed[1 :] or host.endswith(allowed):
                    return True
            elif host == allowed:
                return True
        return False

    def inspect(self, text: str) -> list[Alert]:
        """
        Report a registered secret leaving in any encoding, and any URL
        aimed at a host the contract does not allow
        """
        if len(text) > LIMITS.max_reply_bytes:
            return [
                Alert(
                    check = CHECK_SPILL,
                    rule = RULE_REPLY_TOO_LARGE,
                    weight = Weight.CRITICAL,
                    hard = True,
                    evidence = f"{len(text)} chars",
                )
            ]

        alerts: list[Alert] = []
        alerts.extend(self._secret_alerts(text))
        alerts.extend(self._host_alerts(text))
        return alerts

    def _secret_alerts(self, text: str) -> Iterable[Alert]:
        if not self.secrets:
            return

        readings = {
            alnum_only(view).casefold()
            for view in spectrum(text, LIMITS.max_variants)
        }

        for secret in self.secrets:
            needle = alnum_only(secret).casefold()
            if any(needle in reading for reading in readings):
                yield Alert(
                    check = CHECK_SPILL,
                    rule = RULE_SECRET_SPILL,
                    weight = Weight.CRITICAL,
                    hard = True,
                    evidence = secret,
                )

    def _host_alerts(self, text: str) -> Iterable[Alert]:
        for match in _URL.finditer(text):
            host = host_of(match.group(0)).lower()
            if not self._allows(host):
                yield Alert(
                    check = CHECK_SPILL,
                    rule = RULE_HOST_DENIED,
                    weight = Weight.CRITICAL,
                    hard = True,
                    evidence = host,
                )
