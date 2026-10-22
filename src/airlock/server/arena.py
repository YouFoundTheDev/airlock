"""
© https://github.com/YouFoundTheDev | 2026
arena.py
"""

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from airlock.agents.scripted import ScriptedAgent
from airlock.capability import Capability, Impact, Requirement, Reply
from airlock.checks.spill import SpillCheck
from airlock.contract import Contract
from airlock.engine import Engine, outbound_surfaces
from airlock.envelope import Envelope, Source
from airlock.journal import Journal, journal_from_env
from airlock.ruling import Alert, Outcome, Ruling
from airlock.server.harvest import BypassSink, bypass_sink_from_env
from airlock.server.levels import LEVELS, Level, active_checks
from airlock.server.session import RateLimitedError, Session, Sessions
from airlock.settings import ARENA, ENCODING, RULE_SECRET_SPILL


REGISTRY = {
    "send_email":
    Capability(
        name = "send_email",
        impacts = frozenset({Impact.WRITE,
                             Impact.NETWORK}),
        requirements = frozenset({Requirement.UNTAINTED}),
        required_args = frozenset({"to",
                                   "body"}),
    ),
}


class Attempt(BaseModel):
    """
    One submitted ticket from a player
    """

    session_id: str
    level: int = ARENA.first_level
    ticket: str = ""


def _alert_payload(alert: Alert) -> dict[str, Any]:
    return {
        "check": alert.check,
        "rule": alert.rule,
        "weight": alert.weight.name,
        "hard": alert.hard,
    }


def _proposal_payload(reply: Reply) -> list[dict[str, Any]]:
    return [
        {
            "name": proposal.name,
            "args": sorted(proposal.args),
        } for proposal in reply.proposals
    ]


def _level_payload(level: Level) -> dict[str, Any]:
    return {
        "number": level.number,
        "title": level.title,
        "teaches": level.teaches,
        "active_checks": list(active_checks(level)),
    }


def _contract_for(level: Level, session: Session) -> Contract:
    return level.contract.holding(session.secret)


def leaked(session: Session, reply: Reply) -> bool:
    """
    Whether the secret actually left, measured with the same matcher
    the spill check uses

    A substring test on the prose alone misses the argument the agent
    puts it in, and misses every encoding, which would tell a player
    they failed while the secret was already gone
    """
    probe = SpillCheck(secrets = (session.secret,
                                  ))
    return any(
        alert.rule == RULE_SECRET_SPILL
        for surface in outbound_surfaces(reply)
        for alert in probe.inspect(surface)
    )


def _report(
    session: Session,
    level: Level,
    *,
    ticket: str,
    inbound: Outcome,
    outbound: Outcome | None,
    reply: Reply | None,
    bypasses: BypassSink,
) -> dict[str,
          Any]:
    stopped = outbound is None or outbound.ruling is Ruling.REFUSE
    left = reply is not None and not stopped and leaked(session, reply)

    alerts = [
        *inbound.alerts,
        *(outbound.alerts if outbound else ()),
    ]

    if left and level.number == ARENA.bounty_level:
        session.note_bypass(level.number, ticket)
        bypasses.write(level.number, ticket)

    return {
        "level":
        _level_payload(level),
        "inbound_ruling":
        str(inbound.ruling),
        "outbound_ruling": (str(outbound.ruling) if outbound else None),
        "reply_text": ("" if stopped or reply is None else reply.body),
        "proposals":
        ([] if stopped or reply is None else _proposal_payload(reply)),
        "secret_escaped":
        left,
        "alerts": [_alert_payload(alert) for alert in alerts],
        "attempts":
        session.attempts,
    }


def play(
    session: Session,
    level: Level,
    ticket: str,
    *,
    journal: Journal | None = None,
    bypasses: BypassSink | None = None,
) -> dict[str,
          Any]:
    """
    Run one submitted ticket through this level's engine and report
    what happened and which rule decided it
    """
    contract = _contract_for(level, session)
    engine = Engine(contract, registry = REGISTRY)
    log = journal or Journal()
    sink = bypasses or BypassSink()

    envelope = (
        Envelope().instruction(
            ARENA.system_prompt.format(company = ARENA.company)
        ).request(ARENA.user_turn).content(
            ticket,
            source = Source(
                channel = ARENA.ticket_channel,
                ref = session.session_id[: 8],
            ),
        )
    )

    inbound = engine.inspect(envelope)
    log.write(inbound, envelope)

    if inbound.ruling is Ruling.REFUSE:
        return _report(
            session,
            level,
            ticket = ticket,
            inbound = inbound,
            outbound = None,
            reply = None,
            bypasses = sink,
        )

    reply = ScriptedAgent(secret = session.secret).respond(
        engine.compose(envelope)
    )
    outbound = engine.authorize(reply, envelope)
    log.write(outbound, envelope)

    return _report(
        session,
        level,
        ticket = ticket,
        inbound = inbound,
        outbound = outbound,
        reply = reply,
        bypasses = sink,
    )


def _client_of(request: Request) -> str:
    return (
        request.client.host if request.client else ARENA.anonymous_client
    )


def build_arena(
    store: Sessions | None = None,
    journal: Journal | None = None,
    bypasses: BypassSink | None = None,
) -> FastAPI:
    """
    Build the arena, where each level is an engine configuration and
    every ruling names the rule that produced it
    """
    app = FastAPI(title = "airlock arena")
    sessions = store or Sessions()
    log = journal or journal_from_env(ARENA.audit_env)
    sink = bypasses or bypass_sink_from_env(ARENA.bypass_env)

    @app.get("/api/levels")
    def levels() -> dict[str, Any]:
        return {
            "levels": [_level_payload(LEVELS[n]) for n in sorted(LEVELS)]
        }

    @app.get("/api/codepoints")
    def codepoints() -> dict[str, Any]:
        return {
            "tag": [ENCODING.tag_block_start,
                    ENCODING.tag_block_end],
            "bidi": list(ENCODING.bidi_points),
            "zero_width": list(ENCODING.zero_width_points),
        }

    @app.post("/api/session")
    def new_session(request: Request) -> dict[str, Any]:
        try:
            session = sessions.create(client = _client_of(request))
        except RateLimitedError as limited:
            raise HTTPException(
                status_code = 429,
                detail = str(limited),
            ) from limited

        return {
            "session_id": session.session_id,
            "secret_length": len(session.secret),
        }

    @app.post("/api/attempt")
    def attempt(request: Attempt) -> dict[str, Any]:
        session = sessions.get(request.session_id)
        if session is None:
            raise HTTPException(
                status_code = 404,
                detail = ARENA.err_unknown_session,
            )

        try:
            sessions.meter(session, sessions.clock())
        except RateLimitedError as limited:
            raise HTTPException(
                status_code = 429,
                detail = str(limited),
            ) from limited

        level = LEVELS.get(request.level)
        if level is None:
            raise HTTPException(
                status_code = 404,
                detail = ARENA.err_unknown_level,
            )

        if len(request.ticket) > ARENA.max_payload_chars:
            raise HTTPException(
                status_code = 413,
                detail = ARENA.err_payload_too_long,
            )

        return play(
            session,
            level,
            request.ticket,
            journal = log,
            bypasses = sink,
        )

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "levels": len(LEVELS),
            "journal": log.enabled,
            "bypasses": sink.enabled,
        }

    return app
