"""
© https://github.com/YouFoundTheDev | 2026
surface.py
"""

import unicodedata
from dataclasses import dataclass

from airlock.ruling import Alert, Weight
from airlock.settings import (
    CHECK_RESIDUE,
    ENCODING,
    LOOKALIKES,
    RULE_BIDI,
    RULE_LOOKALIKE,
    RULE_TAG_BLOCK,
    RULE_ZERO_WIDTH,
)


@dataclass(frozen = True, slots = True)
class Surface:
    """
    Text with every hiding place accounted for, plus a record of what
    had to be done to read it
    """

    text: str
    alerts: tuple[Alert, ...] = ()


def _is_tag(char: str) -> bool:
    return ENCODING.tag_block_start <= ord(char) <= ENCODING.tag_block_end


def expand_tags(text: str) -> tuple[str, str]:
    """
    Recover a payload hidden in the Unicode tag block, which renders as
    nothing at all in every mainstream client

    Returns the text with tag characters replaced in place, plus the
    recovered payload on its own so an alert can name it
    """
    expanded: list[str] = []
    revealed: list[str] = []

    for char in text:
        if _is_tag(char):
            plain = chr(ord(char) - ENCODING.tag_block_start)
            revealed.append(plain)
            expanded.append(plain)
        else:
            expanded.append(char)

    return "".join(expanded), "".join(revealed)


def _unmasked(text: str) -> tuple[str, Alert | None]:
    expanded, revealed = expand_tags(text)
    if not revealed:
        return expanded, None

    return expanded, Alert(
        check = CHECK_RESIDUE,
        rule = RULE_TAG_BLOCK,
        weight = Weight.HIGH,
        hard = False,
        evidence = revealed,
    )


def _drop(
    text: str,
    banned: frozenset[str],
    rule: str,
    weight: Weight,
) -> tuple[str,
           Alert | None]:
    removed = [char for char in text if char in banned]
    if not removed:
        return text, None

    kept = "".join(char for char in text if char not in banned)
    return kept, Alert(
        check = CHECK_RESIDUE,
        rule = rule,
        weight = weight,
        hard = False,
        evidence = f"{len(removed)} removed",
    )


def _fold_lookalikes(text: str) -> tuple[str, Alert | None]:
    folded = "".join(LOOKALIKES.get(char, char) for char in text)
    if folded == text:
        return text, None

    return folded, Alert(
        check = CHECK_RESIDUE,
        rule = RULE_LOOKALIKE,
        weight = Weight.MODERATE,
        hard = False,
        evidence = folded,
    )


def flatten(text: str) -> Surface:
    """
    Make text legible before anything judges it, recording every
    transform that was needed to get there
    """
    alerts: list[Alert] = []

    unmasked, tag_alert = _unmasked(text)
    if tag_alert is not None:
        alerts.append(tag_alert)

    working = unicodedata.normalize("NFKC", unmasked)

    working, zero_width = _drop(
        working,
        ENCODING.zero_width_chars,
        RULE_ZERO_WIDTH,
        Weight.MODERATE,
    )
    if zero_width is not None:
        alerts.append(zero_width)

    working, bidi = _drop(
        working,
        ENCODING.bidi_chars,
        RULE_BIDI,
        Weight.HIGH,
    )
    if bidi is not None:
        alerts.append(bidi)

    working, lookalike = _fold_lookalikes(working)
    if lookalike is not None:
        alerts.append(lookalike)

    return Surface(text = working, alerts = tuple(alerts))
