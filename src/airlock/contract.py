"""
© https://github.com/YouFoundTheDev | 2026
contract.py
"""

from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import TypedDict, Unpack

from airlock.capability import Impact
from airlock.ruling import Alert, Ruling, Weight
from airlock.settings import ALL_CHECKS, STRICT_RULES


class ContractError(Exception):
    """
    Raised when a contract asks for a guarantee the engine cannot keep
    """


class ContractChanges(TypedDict, total = False):
    """
    The fields a caller may replace when deriving one contract from
    another
    """

    contract_id: str
    threshold: Weight
    strict: bool
    checks: frozenset[str]
    secrets: tuple[str, ...]
    hosts: tuple[str, ...]
    denied_impacts: frozenset[Impact]


@dataclass(frozen = True, slots = True)
class Contract:
    """
    Which checks run, how heavy a soft alert has to be before it
    refuses, and what the deployment registers as sensitive
    """

    contract_id: str = "default"
    threshold: Weight = Weight.HIGH
    strict: bool = True
    checks: frozenset[str] = frozenset(ALL_CHECKS)
    secrets: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    denied_impacts: frozenset[Impact] = frozenset()

    def changed(self, **changes: Unpack[ContractChanges]) -> Contract:
        """
        A copy of this contract with named fields replaced
        """
        return replace(self, **changes)

    def without(self, *names: str) -> Contract:
        """
        A copy with the named checks switched off
        """
        return replace(self, checks = self.checks.difference(names))

    def only(self, *names: str) -> Contract:
        """
        A copy that runs exactly the named checks
        """
        return replace(self, checks = frozenset(names))

    def holding(self, secret: str) -> Contract:
        """
        A copy that treats this one value as a secret
        """
        return replace(
            self,
            secrets = (secret,
                       )
        )


def promote(
    alerts: Sequence[Alert],
    contract: Contract,
) -> list[Alert]:
    """
    Turn soft phrasing alerts into hard ones where the contract says
    external content may carry no instruction shapes at all
    """
    if not contract.strict:
        return list(alerts)

    return [
        replace(alert,
                hard = True) if alert.rule in STRICT_RULES else alert
        for alert in alerts
    ]


def resolve(
    alerts: Sequence[Alert],
    contract: Contract,
) -> Ruling:
    """
    Collapse alerts into a ruling, keeping hard violations out of the
    scored comparison entirely
    """
    if any(alert.hard for alert in alerts):
        return Ruling.REFUSE

    scored = [
        alert.weight
        for alert in alerts
        if not alert.hard and alert.weight > Weight.INFO
    ]
    if scored and max(scored) >= contract.threshold:
        return Ruling.REFUSE

    return Ruling.PERMIT
