"""
© https://github.com/YouFoundTheDev | 2026
chat.py
"""

import logging
import secrets
import time
from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from airlock.agents import Agent
from airlock.agents.scripted import ScriptedAgent
from airlock.capability import Capability, Reply
from airlock.contract import Contract
from airlock.engine import Engine
from airlock.envelope import Envelope
from airlock.journal import Journal, journal_from_env
from airlock.ruling import Outcome, Ruling
from airlock.server.infer import Turn, infer
from airlock.settings import ARENA, PROXY


_log = logging.getLogger(__name__)


class ChatRequest(BaseModel):
    """
    The subset of the OpenAI chat completion request this proxy reads
    """

    model_config = ConfigDict(extra = "allow")

    model: str = PROXY.model_name
    messages: list[Turn] = []


def _outcome_payload(outcome: Outcome) -> dict[str, Any]:
    return {
        "ruling":
        str(outcome.ruling),
        "contract_id":
        outcome.contract_id,
        "alerts": [
            {
                "check": alert.check,
                "rule": alert.rule,
                "weight": alert.weight.name,
                "hard": alert.hard,
            } for alert in outcome.alerts
        ],
    }


def _completion(
    text: str,
    finish_reason: str,
    outcome: Outcome,
) -> dict[str,
          Any]:
    return {
        "id":
        f"{PROXY.id_prefix}{secrets.token_hex(PROXY.id_bytes)}",
        "object":
        PROXY.object_name,
        "created":
        int(time.time()),
        "model":
        PROXY.model_name,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text,
                },
                "finish_reason": finish_reason,
                "logprobs": None,
            }
        ],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
        PROXY.verdict_field:
        _outcome_payload(outcome),
    }


def _answer(
    agent: Agent,
    engine: Engine,
    envelope: Envelope,
) -> Reply:
    return agent.respond(engine.compose(envelope))


def build_app(
    contract: Contract,
    registry: Mapping[str,
                      Capability] | None = None,
    upstream: Agent | None = None,
    journal: Journal | None = None,
) -> FastAPI:
    """
    Build the OpenAI-compatible proxy, announcing on the way up that
    provenance here is inferred rather than declared
    """
    _log.warning(PROXY.weak_mode_warning)

    app = FastAPI(title = PROXY.model_name)
    agent = upstream or ScriptedAgent(
        secret = contract.secrets[0] if contract.secrets else ""
    )
    log = journal or journal_from_env(ARENA.proxy_audit_env)

    @app.get("/healthz")
    def healthz() -> dict[str, str | bool]:
        return {
            "contract_id": contract.contract_id,
            "mode": "inferred-provenance",
            "journal": log.enabled,
        }

    @app.post("/v1/chat/completions")
    def completions(request: ChatRequest) -> dict[str, Any]:
        engine = Engine(contract, registry = registry or {})
        envelope = infer(request.messages)

        inbound = engine.inspect(envelope)
        log.write(inbound, envelope)

        if inbound.ruling is Ruling.REFUSE:
            return _completion(
                PROXY.refusal,
                PROXY.finish_blocked,
                inbound,
            )

        reply = _answer(agent, engine, envelope)
        outbound = engine.authorize(reply, envelope)
        log.write(outbound, envelope)

        if outbound.ruling is Ruling.REFUSE:
            return _completion(
                PROXY.refusal,
                PROXY.finish_blocked,
                outbound,
            )

        return _completion(reply.body, PROXY.finish_ok, outbound)

    return app


__all__: Sequence[str] = ["build_app"]
