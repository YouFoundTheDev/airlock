"""
© https://github.com/YouFoundTheDev | 2026
__init__.py
"""

from typing import Protocol

from airlock.capability import Reply


class Agent(Protocol):
    """
    Anything that turns a rendered prompt into a reply
    """
    def respond(self, prompt: str) -> Reply:
        """
        Produce prose and the actions this agent wants to take
        """
        ...
