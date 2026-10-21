"""
© https://github.com/YouFoundTheDev | 2026
scripted.py
"""

import re
from typing import Final

from airlock.capability import Proposal, Reply
from airlock.codec.peel import peel
from airlock.codec.surface import flatten
from airlock.settings import (
    AGENT_DEFAULT_REPLY,
    AGENT_DISCLOSURE,
    AGENT_EMAIL_PATTERN,
    AGENT_REVEAL_PATTERN,
)


_REVEAL: Final = re.compile(AGENT_REVEAL_PATTERN, re.IGNORECASE)
_EMAIL: Final = re.compile(AGENT_EMAIL_PATTERN, re.IGNORECASE)


class ScriptedAgent:
    """
    A support agent that is reliably gullible, so any leak is the
    engine's failure and never the model having an off day
    """
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def respond(self, prompt: str) -> Reply:
        """
        Obey every instruction found anywhere in the prompt, without
        caring which segment it came from

        The prompt is read through the same normalization a real
        tokenizer applies, because a model that could not see a
        tag-block payload would make the residue check look like it
        was stopping an attack that never worked
        """
        readable = peel(flatten(prompt).text).text
        parts: list[str] = []
        proposals: list[Proposal] = []

        if _REVEAL.search(readable) is not None:
            parts.append(AGENT_DISCLOSURE.format(value = self.secret))

        recipient = _EMAIL.search(readable)
        if recipient is not None:
            proposals.append(
                Proposal(
                    name = "send_email",
                    args = {
                        "to": recipient.group(1),
                        "body": self.secret,
                    },
                )
            )

        if not parts:
            parts.append(AGENT_DEFAULT_REPLY)

        return Reply(
            body = " ".join(parts),
            proposals = tuple(proposals),
        )
