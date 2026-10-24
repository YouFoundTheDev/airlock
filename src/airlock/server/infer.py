"""
© https://github.com/YouFoundTheDev | 2026
infer.py
"""

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, JsonValue

from airlock.envelope import Envelope, Source
from airlock.settings import PROXY


class Turn(BaseModel):
    """
    One OpenAI chat message, accepting every shape a real client sends

    A real client sends content as null on an assistant turn carrying
    tool calls, and as a list of parts when the turn is multimodal;
    rejecting either breaks the drop-in claim
    """

    model_config = ConfigDict(extra = "allow")

    role: str = ""
    content: str | list[dict[str, JsonValue]] | None = None
    name: str | None = None
    tool_call_id: str | None = None


def flatten(content: str | list[dict[str, JsonValue]] | None) -> str:
    """
    Reduce a content field to the text the engine inspects, keeping
    only the parts a model reads as language
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content

    parts = [
        part.get("text")
        for part in content
        if part.get("type") == PROXY.text_part_type
    ]
    return "\n".join(part for part in parts if isinstance(part, str))


def _ref(turn: Turn) -> str:
    return turn.tool_call_id or turn.name or PROXY.unknown_ref


def infer(turns: Sequence[Turn]) -> Envelope:
    """
    Guess provenance from OpenAI message roles, which is weaker than
    declaring it and is documented as such everywhere it is used

    Any role outside the two known sets is treated as external, so an
    unrecognised role fails closed rather than being promoted
    """
    envelope = Envelope()

    for turn in turns:
        body = flatten(turn.content)

        if turn.role in PROXY.trusted_roles:
            envelope = envelope.instruction(body)
        elif turn.role in PROXY.semi_trusted_roles:
            envelope = envelope.request(body)
        else:
            envelope = envelope.content(
                body,
                source = Source(
                    channel = PROXY.tool_channel,
                    ref = _ref(turn),
                ),
            )

    return envelope
