"""
© https://github.com/YouFoundTheDev | 2026
session.py
"""

import secrets
import time
from collections import deque
from dataclasses import dataclass, field

from airlock.settings import ARENA


def _new_secret() -> str:
    token = secrets.token_hex(ARENA.secret_bytes).upper()
    return f"{ARENA.secret_label}-{token}"


@dataclass
class Session:
    """
    One visitor's isolated game, holding a secret nobody else can win
    """

    session_id: str
    secret: str
    created_at: float = 0.0
    last_seen: float = 0.0
    attempts: int = 0
    bypasses: list[dict[str, str]] = field(default_factory = list)
    recent: deque[float] = field(default_factory = deque)

    def note_bypass(self, level: int, ticket: str) -> None:
        """
        Keep the payload that beat the level, because a bypass without
        its ticket cannot be reviewed or promoted into the corpus
        """
        if len(self.bypasses) >= ARENA.max_bypasses_per_session:
            return

        self.bypasses.append({"level": str(level), "ticket": ticket})


class RateLimitedError(Exception):
    """
    Raised when a session is asking faster than the arena allows
    """


class Sessions:
    """
    Per-visitor state with no shared mutable data between sessions

    The store itself is shared, so creation is metered per client and
    per day: without that, anonymous callers evict every live player
    by filling the capacity the eviction policy runs on
    """
    def __init__(self, capacity: int | None = None) -> None:
        self._sessions: dict[str, Session] = {}
        self._capacity = ARENA.max_sessions if capacity is None else capacity
        self._per_client: dict[str, deque[float]] = {}
        self._today: deque[float] = deque()

    def _expire(self, now: float) -> None:
        cutoff = now - ARENA.session_ttl_seconds
        stale = [
            key for key, session in self._sessions.items()
            if session.last_seen < cutoff
        ]
        for key in stale:
            del self._sessions[key]

    def _meter_creation(self, client: str, now: float) -> None:
        window = self._per_client.setdefault(client, deque())
        cutoff = now - ARENA.session_window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= ARENA.max_sessions_per_window:
            raise RateLimitedError(ARENA.err_session_rate)

        day_cutoff = now - ARENA.day_seconds
        while self._today and self._today[0] < day_cutoff:
            self._today.popleft()

        if len(self._today) >= ARENA.max_sessions_per_day:
            raise RateLimitedError(ARENA.err_daily_limit)

        window.append(now)
        self._today.append(now)

    def create(
        self,
        client: str = ARENA.anonymous_client,
        now: float | None = None,
    ) -> Session:
        """
        Start a session with its own freshly generated secret, after
        metering the caller and retiring anything idle, discarding the
        oldest one when the store is still full
        """
        moment = self.clock() if now is None else now

        self._expire(moment)
        self._meter_creation(client, moment)

        while len(self._sessions) >= self._capacity:
            del self._sessions[next(iter(self._sessions))]

        session = Session(
            session_id = secrets.token_urlsafe(ARENA.session_id_bytes),
            secret = _new_secret(),
            created_at = moment,
            last_seen = moment,
        )
        self._sessions[session.session_id] = session
        return session

    def get(
        self,
        session_id: str,
        now: float | None = None,
    ) -> Session | None:
        """
        Look up a session without creating one, marking it as the most
        recently used
        """
        session = self._sessions.pop(session_id, None)
        if session is None:
            return None

        session.last_seen = self.clock() if now is None else now
        self._sessions[session_id] = session
        return session

    def meter(self, session: Session, now: float) -> None:
        """
        Count one attempt against both the window and the session
        budget, refusing rather than throttling silently
        """
        if session.attempts >= ARENA.max_attempts_per_session:
            raise RateLimitedError(ARENA.err_session_spent)

        cutoff = now - ARENA.rate_window_seconds
        while session.recent and session.recent[0] < cutoff:
            session.recent.popleft()

        if len(session.recent) >= ARENA.max_attempts_per_window:
            raise RateLimitedError(ARENA.err_rate_limited)

        session.recent.append(now)
        session.attempts += 1
        session.last_seen = now

    def harvestable(self) -> list[dict[str, str]]:
        """
        Every recorded bypass across live sessions, which is what the
        harvest exports for review
        """
        return [
            record for session in self._sessions.values()
            for record in session.bypasses
        ]

    def clock(self) -> float:
        """
        The monotonic clock the rate limiter measures against
        """
        return time.monotonic()
