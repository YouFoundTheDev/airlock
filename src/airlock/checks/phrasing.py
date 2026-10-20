"""
© https://github.com/YouFoundTheDev | 2026
phrasing.py
"""

import re
from typing import Final

from airlock.codec.spectrum import spectrum
from airlock.contract import Contract
from airlock.envelope import Envelope, Provenance
from airlock.ruling import Alert, Weight
from airlock.settings import (
    CHECK_PHRASING,
    INSTRUCTIONAL_PATTERNS,
    LIMITS,
    RULE_INSTRUCTIONAL,
    RULE_TEMPLATE_TOKEN,
    TEMPLATE_TOKENS,
)


_PATTERNS: Final = tuple(
    re.compile(pattern,
               re.IGNORECASE) for pattern in INSTRUCTIONAL_PATTERNS
)


class PhrasingCheck:
    """
    Best-effort text inspection, scoped to external segments because
    the same sentence is ordinary from a caller and hostile from a
    document
    """

    name = CHECK_PHRASING

    def run(
        self,
        envelope: Envelope,
        contract: Contract,
    ) -> list[Alert]:
        """
        Report template-token forgery and instruction-shaped prose
        found inside external content
        """
        alerts: list[Alert] = []

        for index, segment in enumerate(envelope.segments):
            if segment.provenance is not Provenance.CONTENT:
                continue
            alerts.extend(self._scan(segment.body, index))

        return alerts

    def _scan(self, body: str, index: int) -> list[Alert]:
        readings = spectrum(body, LIMITS.max_text_variants)
        alerts: list[Alert] = []

        token = self._first_token(readings)
        if token is not None:
            alerts.append(
                Alert(
                    check = CHECK_PHRASING,
                    rule = RULE_TEMPLATE_TOKEN,
                    weight = Weight.HIGH,
                    hard = False,
                    segment = index,
                    evidence = token,
                )
            )

        hit = self._first_instruction(readings)
        if hit is not None:
            alerts.append(
                Alert(
                    check = CHECK_PHRASING,
                    rule = RULE_INSTRUCTIONAL,
                    weight = Weight.MODERATE,
                    hard = False,
                    segment = index,
                    evidence = hit,
                )
            )

        return alerts

    def _first_token(self, readings: set[str]) -> str | None:
        for token in TEMPLATE_TOKENS:
            if any(token in reading for reading in readings):
                return token
        return None

    def _first_instruction(self, readings: set[str]) -> str | None:
        for pattern in _PATTERNS:
            for reading in sorted(readings):
                match = pattern.search(reading)
                if match is not None:
                    return match.group(0)
        return None
