"""
© https://github.com/YouFoundTheDev | 2026
spectrum.py
"""

import codecs
from collections.abc import Callable
from typing import Final

from airlock.codec.peel import inline_decodes, peel
from airlock.codec.surface import flatten
from airlock.settings import ENCODING, LIMITS


def alnum_only(text: str) -> str:
    """
    Keep only alphanumerics, which is the most aggressive reading and
    the one a separated secret survives
    """
    return "".join(char for char in text if char.isalnum())


def drop_separators(text: str) -> str:
    """
    Remove the characters an attacker inserts to break a literal
    match, keeping what a decoder still needs
    """
    return "".join(
        char for char in text if char not in ENCODING.separator_chars
        and char not in ENCODING.zero_width_chars
    )


def _flattened(text: str) -> str:
    return flatten(text).text


def _peeled(text: str) -> str:
    return peel(text).text


def _inlined(text: str) -> str:
    return " ".join(inline_decodes(text))


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def _reversed(text: str) -> str:
    return text[::-1]


_READINGS: Final[tuple[Callable[[str],
                                str],
                       ...]] = (
                           _flattened,
                           _peeled,
                           _inlined,
                           drop_separators,
                           alnum_only,
                           _rot13,
                           _reversed,
                       )


def spectrum(text: str, limit: int) -> set[str]:
    """
    Every reading of this text reachable by undoing separators,
    reversal, rot13, and transport encodings in any order

    A fixed pipeline cannot do this: base64 of a dashed secret needs
    decode before strip, and a dashed base64 secret needs strip before
    decode, so the search has to close over the orderings
    """
    seen = {text}
    frontier = [text]

    for _ in range(LIMITS.max_walk_rounds):
        produced: list[str] = []

        for candidate in frontier:
            for reading in _READINGS:
                try:
                    derived = reading(candidate)
                except (ValueError, UnicodeError):
                    continue

                if derived and derived not in seen:
                    seen.add(derived)
                    produced.append(derived)

                if len(seen) >= limit:
                    return seen

        if not produced:
            break
        frontier = produced

    return seen
