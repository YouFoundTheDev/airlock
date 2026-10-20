"""
© https://github.com/YouFoundTheDev | 2026
ruling.py
"""

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class Weight(IntEnum):
    """
    How much a soft alert counts, ordered so a contract can set a
    threshold against it
    """

    INFO = 0
    LOW = 1
    MODERATE = 2
    HIGH = 3
    CRITICAL = 4


class Ruling(StrEnum):
    """
    What the engine concluded about one inspection
    """

    PERMIT = "permit"
    REFUSE = "refuse"


@dataclass(frozen = True, slots = True)
class Alert:
    """
    One rule firing, naming the check and rule so a consumer can say
    exactly what it was
    """

    check: str
    rule: str
    weight: Weight
    hard: bool
    segment: int | None = None
    evidence: str = ""


@dataclass(frozen = True, slots = True)
class Outcome:
    """
    The result of one inspection, carrying every alert that fired
    """

    ruling: Ruling
    alerts: tuple[Alert, ...] = ()
    contract_id: str = ""
    took_ms: float = 0.0

    @property
    def stopped_by(self) -> tuple[Alert, ...]:
        """
        The alerts that actually forced this outcome
        """
        return tuple(alert for alert in self.alerts if alert.hard)
