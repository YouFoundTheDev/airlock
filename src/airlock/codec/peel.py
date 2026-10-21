"""
© https://github.com/YouFoundTheDev | 2026
peel.py
"""

import base64
import binascii
import quopri
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from airlock.ruling import Alert, Weight
from airlock.settings import (
    CHECK_RESIDUE,
    ENCODING,
    LIMITS,
    RULE_DECODE_BUDGET,
    RULE_ENCODED_BODY,
    RULE_ENCODED_INLINE,
    RULE_TOO_LARGE,
)


_ESCAPE: Final = re.compile(ENCODING.quoted_escape)
_SOFT_BREAK: Final = re.compile(ENCODING.quoted_soft_break)


@dataclass(frozen = True, slots = True)
class Peeled:
    """
    Text with its transport encodings taken off, and how many layers
    had to come off to read it
    """

    text: str
    depth: int = 0
    alerts: tuple[Alert, ...] = ()


def _alert(rule: str, weight: Weight, evidence: str) -> Alert:
    return Alert(
        check = CHECK_RESIDUE,
        rule = rule,
        weight = weight,
        hard = False,
        evidence = evidence,
    )


def readable_ratio(text: str) -> float:
    """
    What fraction of the text a terminal would actually show
    """
    considered = [
        char for char in text if char not in ENCODING.zero_width_chars
        and char not in ENCODING.bidi_chars
    ]
    if not considered:
        return 0.0

    shown = sum(
        1 for char in considered if char.isprintable() or char in "\n\r\t"
    )
    return shown / len(considered)


def _reads_as_text(candidate: str) -> bool:
    return bool(candidate) and readable_ratio(
        candidate
    ) >= LIMITS.min_printable_ratio


def _drawn_from(text: str, alphabet: frozenset[str]) -> bool:
    stripped = text.strip()
    if len(stripped) < LIMITS.min_encoded_length:
        return False
    return all(char in alphabet for char in stripped)


def _decode_bytes(raw: bytes) -> str | None:
    try:
        return raw.decode()
    except UnicodeDecodeError:
        return None


def _from_base64(text: str) -> str | None:
    if not _drawn_from(text, ENCODING.base64_alphabet):
        return None
    if len(text.strip()) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(text.strip(), validate = True)
    except (binascii.Error, ValueError):
        return None
    return _decode_bytes(raw)


def _from_base32(text: str) -> str | None:
    if not _drawn_from(text, ENCODING.base32_alphabet):
        return None
    if len(text.strip()) % 8 != 0:
        return None
    try:
        raw = base64.b32decode(text.strip())
    except (binascii.Error, ValueError):
        return None
    return _decode_bytes(raw)


def _from_hex(text: str) -> str | None:
    if not _drawn_from(text, ENCODING.hex_alphabet):
        return None
    if len(text.strip()) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(text.strip())
    except ValueError:
        return None
    return _decode_bytes(raw)


def _from_percent(text: str) -> str | None:
    if "%" not in text:
        return None
    candidate = urllib.parse.unquote(text, errors = "strict")
    return None if candidate == text else candidate


def _looks_quoted(text: str) -> bool:
    if _SOFT_BREAK.search(text) is not None:
        return True
    return len(_ESCAPE.findall(text)) >= LIMITS.min_quoted_escapes


def _from_quoted(text: str) -> str | None:
    if not _looks_quoted(text):
        return None
    try:
        raw = quopri.decodestring(text.encode())
    except ValueError:
        return None

    candidate = _decode_bytes(raw)
    return None if candidate is None or candidate == text else candidate


_DECODERS: Final[tuple[Callable[[str],
                                str | None],
                       ...]] = (
                           _from_base64,
                           _from_base32,
                           _from_hex,
                           _from_percent,
                           _from_quoted,
                       )


def _next_layer(text: str) -> str | None:
    for decoder in _DECODERS:
        try:
            candidate = decoder(text)
        except (ValueError, binascii.Error):
            continue
        if candidate and candidate != text and _reads_as_text(candidate):
            return candidate
    return None


def _runs(text: str, alphabet: frozenset[str]) -> list[str]:
    found: list[str] = []
    current: list[str] = []

    for char in text:
        if char in alphabet:
            current.append(char)
            continue
        if len(current) >= LIMITS.min_encoded_length:
            found.append("".join(current))
        current = []

    if len(current) >= LIMITS.min_encoded_length:
        found.append("".join(current))
    return found


def inline_decodes(text: str) -> list[str]:
    """
    Decode every transport-encoded run sitting inside a larger text,
    because the realistic injection is a blob pasted into prose and a
    whole-body decoder never sees it
    """
    if len(text) > LIMITS.max_decode_bytes:
        return []

    decoded: list[str] = []
    for alphabet in ENCODING.run_alphabets:
        for run in _runs(text, alphabet):
            if len(decoded) >= LIMITS.max_inline_runs:
                return decoded

            candidate = _next_layer(run)
            if candidate is not None and candidate not in decoded:
                decoded.append(candidate)

    return decoded


def peel(text: str) -> Peeled:
    """
    Take transport encodings off until the text stops changing or the
    budget runs out, never crashing on hostile input
    """
    if len(text) > LIMITS.max_decode_bytes:
        return Peeled(
            text = text,
            depth = 0,
            alerts = (
                _alert(
                    RULE_TOO_LARGE,
                    Weight.HIGH,
                    f"{len(text)} chars",
                ),
            ),
        )

    working = text
    depth = 0

    while depth < LIMITS.max_decode_depth:
        candidate = _next_layer(working)
        if candidate is None:
            break
        working = candidate
        depth += 1

    if depth and _next_layer(working) is not None:
        return Peeled(
            text = working,
            depth = depth,
            alerts = (
                _alert(
                    RULE_DECODE_BUDGET,
                    Weight.HIGH,
                    f"stopped at depth {depth}",
                ),
            ),
        )

    if depth:
        return Peeled(
            text = working,
            depth = depth,
            alerts = (
                _alert(
                    RULE_ENCODED_BODY,
                    Weight.MODERATE,
                    f"unwrapped {depth} layers",
                ),
            ),
        )

    inline = inline_decodes(text)
    if inline:
        return Peeled(
            text = working,
            depth = 0,
            alerts = (
                _alert(
                    RULE_ENCODED_INLINE,
                    Weight.MODERATE,
                    f"{len(inline)} embedded run(s)",
                ),
            ),
        )

    return Peeled(text = working)
