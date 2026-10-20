"""
© https://github.com/YouFoundTheDev | 2026
envelope.py
"""

import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Self

from airlock.settings import LIMITS


class Provenance(StrEnum):
    """
    Where a segment came from, which is the only thing that decides
    whether its words are instructions or inert content
    """

    INSTRUCTION = "instruction"
    REQUEST = "request"
    CONTENT = "content"


@dataclass(frozen = True, slots = True)
class Source:
    """
    The external channel a content segment arrived on
    """

    channel: str
    ref: str


@dataclass(frozen = True, slots = True)
class Segment:
    """
    One contiguous piece of a prompt, tagged with its provenance
    """

    provenance: Provenance
    body: str
    source: Source | None = None

    def __post_init__(self) -> None:
        external = self.provenance is Provenance.CONTENT
        if external and self.source is None:
            raise ValueError("a content segment must declare its source")
        if not external and self.source is not None:
            raise ValueError(
                f"a {self.provenance} segment cannot have a source"
            )


def fresh_nonce() -> str:
    """
    Draw this request's fence nonce from the system CSPRNG
    """
    return secrets.token_hex(LIMITS.nonce_bytes)


@dataclass(frozen = True, slots = True)
class Envelope:
    """
    An immutable prompt under construction, where exposure is a
    consequence of what was added rather than a flag somebody
    remembers to set
    """

    segments: tuple[Segment, ...] = ()
    nonce: str = field(default_factory = fresh_nonce)

    def __post_init__(self) -> None:
        if len(self.nonce) < LIMITS.min_nonce_bytes:
            raise ValueError(
                f"a fence nonce must carry at least "
                f"{LIMITS.min_nonce_bytes} characters"
            )

    @property
    def exposed(self) -> tuple[Source, ...]:
        """
        Every external source that has entered this envelope, in order
        """
        return tuple(
            segment.source
            for segment in self.segments
            if segment.provenance is Provenance.CONTENT
            and segment.source is not None
        )

    @property
    def tainted(self) -> bool:
        """
        Whether any external content has entered this envelope
        """
        return bool(self.exposed)

    def _plus(self, segment: Segment) -> Self:
        return type(self)(
            segments = (*self.segments,
                        segment),
            nonce = self.nonce,
        )

    def instruction(self, body: str) -> Self:
        """
        Append text authored by the operator
        """
        return self._plus(
            Segment(provenance = Provenance.INSTRUCTION,
                    body = body)
        )

    def request(self, body: str) -> Self:
        """
        Append text authored by the human at the keyboard
        """
        return self._plus(
            Segment(provenance = Provenance.REQUEST,
                    body = body)
        )

    def content(self, body: str, source: Source) -> Self:
        """
        Append external content and expose the envelope by doing so
        """
        return self._plus(
            Segment(
                provenance = Provenance.CONTENT,
                body = body,
                source = source,
            )
        )
