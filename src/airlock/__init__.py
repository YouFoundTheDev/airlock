"""
© https://github.com/YouFoundTheDev | 2026
__init__.py
"""

from airlock.capability import (
    Capability,
    Impact,
    Proposal,
    Reply,
    Requirement,
)
from airlock.contract import Contract, ContractError
from airlock.engine import Engine, compose, outbound_surfaces
from airlock.envelope import Envelope, Provenance, Segment, Source
from airlock.ruling import Alert, Outcome, Ruling, Weight


__version__ = "0.1.0"

__all__ = [
    "Alert",
    "Capability",
    "Contract",
    "ContractError",
    "Engine",
    "Envelope",
    "Impact",
    "Outcome",
    "Proposal",
    "Provenance",
    "Reply",
    "Requirement",
    "Ruling",
    "Segment",
    "Source",
    "Weight",
    "__version__",
    "compose",
    "outbound_surfaces",
]
