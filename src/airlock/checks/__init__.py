"""
© https://github.com/YouFoundTheDev | 2026
__init__.py
"""

from typing import Protocol

from airlock.contract import Contract
from airlock.envelope import Envelope
from airlock.ruling import Alert


class InboundCheck(Protocol):
    """
    One inspection stage over an envelope, which reports what it found
    and never decides what to do about it
    """

    name: str

    def run(
        self,
        envelope: Envelope,
        contract: Contract,
    ) -> list[Alert]:
        """
        Report every rule that fired against this envelope
        """
        ...
