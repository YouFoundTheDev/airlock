"""
© https://github.com/YouFoundTheDev | 2026
journal.py
"""

import hashlib
import os
from pathlib import Path

import orjson

from airlock.envelope import Envelope, Segment
from airlock.ruling import Alert, Outcome
from airlock.settings import LIMITS


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()
                          ).hexdigest()[: LIMITS.journal_digest_chars]


def _segment_entry(segment: Segment) -> dict[str, str | None]:
    source = segment.source
    return {
        "provenance":
        str(segment.provenance),
        "source": (
            f"{source.channel}:{_digest(source.ref)}"
            if source is not None else None
        ),
    }


def _alert_entry(alert: Alert) -> dict[str, object]:
    return {
        "check": alert.check,
        "rule": alert.rule,
        "weight": alert.weight.name,
        "hard": alert.hard,
        "segment": alert.segment,
        "evidence_digest": _digest(alert.evidence),
    }


def record(outcome: Outcome, envelope: Envelope) -> bytes:
    """
    Serialise one inspection as a JSONL line that carries no attacker
    content, so the log is safe to keep

    The source ref is digested along with the evidence because in
    proxy mode it comes straight out of the request body
    """
    payload = {
        "contract_id": outcome.contract_id,
        "ruling": str(outcome.ruling),
        "took_ms": round(outcome.took_ms,
                         3),
        "segments":
        [_segment_entry(segment) for segment in envelope.segments],
        "alerts": [_alert_entry(alert) for alert in outcome.alerts],
    }
    return orjson.dumps(payload) + b"\n"


class Journal:
    """
    An append-only JSONL sink that writes nothing at all when no path
    is configured, so the default posture keeps no records
    """
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        if path is not None:
            path.parent.mkdir(parents = True, exist_ok = True)

    @property
    def enabled(self) -> bool:
        """
        Whether this journal has somewhere to write
        """
        return self.path is not None

    def write(self, outcome: Outcome, envelope: Envelope) -> None:
        """
        Append one record, doing nothing when the journal is disabled
        """
        if self.path is None:
            return

        with self.path.open("ab") as sink:
            sink.write(record(outcome, envelope))


def journal_from_env(variable: str) -> Journal:
    """
    Build the sink named by an environment variable, disabled when the
    variable is unset or empty
    """
    raw = os.environ.get(variable, "").strip()
    return Journal(Path(raw) if raw else None)
