"""
© https://github.com/YouFoundTheDev | 2026
levels.py
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ruamel.yaml import YAML

from airlock.contract import Contract
from airlock.settings import ALL_CHECKS, ARENA


POLICY_DIR: Final = Path(__file__).parent / "policies"


@dataclass(frozen = True)
class Level:
    """
    One rung of the ladder, which is a firewall configuration and a
    sentence about what turning that check on teaches
    """

    number: int
    title: str
    teaches: str
    contract: Contract


def _load(path: Path) -> Level:
    document = YAML(typ = "safe").load(path.read_text())
    number = int(path.stem.rsplit("-", 1)[1])

    return Level(
        number = number,
        title = document["title"],
        teaches = document["teaches"],
        contract = Contract(
            contract_id = document["id"],
            strict = document["strict"],
            checks = frozenset(document.get("checks") or ()),
            hosts = ARENA.allowed_hosts,
        ),
    )


def load_levels() -> dict[int, Level]:
    """
    Read every level policy, keyed by its number
    """
    return {
        level.number: level
        for level in
        (_load(path) for path in sorted(POLICY_DIR.glob("*.yaml")))
    }


LEVELS: Final = load_levels()


def active_checks(level: Level) -> tuple[str, ...]:
    """
    Name the checks this level has switched on, so a player is never
    left guessing whether they beat a check or were handed the win
    """
    return tuple(
        name for name in ALL_CHECKS if name in level.contract.checks
    )
