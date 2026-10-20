"""
© https://github.com/YouFoundTheDev | 2026
capability.py
"""

from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel, JsonValue


class Impact(StrEnum):
    """
    What a capability does to the world if it runs
    """

    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    SPEND = "spend"


class Requirement(StrEnum):
    """
    A condition the engine checks before a proposal is granted
    """

    UNTAINTED = "untainted"
    CONFIRMED = "confirmed"
    ALLOWLISTED = "allowlisted"


@dataclass(frozen = True, slots = True)
class Capability:
    """
    Something the model may propose, and the conditions under which
    the engine will grant it
    """

    name: str
    impacts: frozenset[Impact] = frozenset()
    requirements: frozenset[Requirement] = frozenset()
    required_args: frozenset[str] = frozenset()
    optional_args: frozenset[str] = frozenset()
    allowlist: dict[str, frozenset[str]] = field(default_factory = dict)
    arg_schema: type[BaseModel] | None = None

    @property
    def accepted_args(self) -> frozenset[str]:
        """
        Every argument name this capability accepts, and no others
        """
        return self.required_args | self.optional_args


@dataclass(frozen = True, slots = True)
class Proposal:
    """
    What the model asked to do, which is a request and never a grant
    """

    name: str
    args: dict[str, JsonValue] = field(default_factory = dict)
    confirmed: bool = False


@dataclass(frozen = True, slots = True)
class Reply:
    """
    What the model produced, both the prose and the actions it wants
    """

    body: str = ""
    proposals: tuple[Proposal, ...] = ()


def flatten_arg(value: JsonValue) -> str:
    """
    Flatten one argument value to the text spill control has to scan,
    because a secret nested in a list or an object still leaves
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(
            f"{key} {flatten_arg(item)}" for key, item in value.items()
        )
    if isinstance(value, list):
        return " ".join(flatten_arg(item) for item in value)
    return str(value)
