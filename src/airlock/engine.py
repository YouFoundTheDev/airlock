"""
© https://github.com/YouFoundTheDev | 2026
engine.py
"""

import time
from collections.abc import Mapping

from airlock.capability import Capability, Reply, flatten_arg
from airlock.checks import InboundCheck
from airlock.checks.fence import FenceCheck
from airlock.checks.grant import GrantCheck
from airlock.checks.phrasing import PhrasingCheck
from airlock.checks.residue import ResidueCheck
from airlock.checks.spill import SpillCheck
from airlock.contract import Contract, ContractError, promote, resolve
from airlock.envelope import Envelope, Provenance, Segment
from airlock.ruling import Alert, Outcome, Weight
from airlock.settings import (
    CHECK_FENCE,
    CHECK_GRANT,
    CHECK_PHRASING,
    CHECK_RESIDUE,
    CHECK_SPILL,
    FENCES,
    INBOUND_CHECKS,
    LIMITS,
    RULE_FAULT,
    RULE_MUTED,
    RULE_REPLY_TOO_LARGE,
    SECRET_REJECTED,
)


def _enclose(segment: Segment, nonce: str) -> str:
    source = segment.source
    channel = source.channel if source is not None else "unknown"
    ref = source.ref if source is not None else "unknown"

    opened = FENCES.open.format(
        nonce = nonce,
        channel = channel,
        ref = ref,
    )
    return f"{opened}\n{segment.body}\n{FENCES.close.format(nonce = nonce)}"


def compose(envelope: Envelope) -> str:
    """
    Build the prompt, fencing every external segment with a delimiter
    its own content cannot forge
    """
    parts: list[str] = []
    for segment in envelope.segments:
        if segment.provenance is Provenance.CONTENT:
            parts.append(_enclose(segment, envelope.nonce))
        else:
            parts.append(segment.body)

    return "\n".join(parts)


def outbound_surfaces(reply: Reply) -> tuple[str, ...]:
    """
    Every piece of a reply that leaves the boundary, which is the prose
    and every proposal argument value flattened to text
    """
    return (
        reply.body,
        *(
            flatten_arg(value)
            for proposal in reply.proposals
            for value in proposal.args.values()
        ),
    )


class Engine:
    """
    Runs every enabled check, fails closed on any of them, and
    resolves what they found into a ruling
    """
    def __init__(
        self,
        contract: Contract,
        registry: Mapping[str,
                          Capability] | None = None,
    ) -> None:
        self.contract = contract
        self.inbound: dict[str,
                           InboundCheck] = {
                               CHECK_RESIDUE: ResidueCheck(),
                               CHECK_PHRASING: PhrasingCheck(),
                               CHECK_FENCE: FenceCheck(),
                           }
        self.grant = GrantCheck(registry or {})
        self.spill = SpillCheck(
            secrets = contract.secrets,
            hosts = contract.hosts,
        )

        if self.spill.rejected:
            raise ContractError(
                SECRET_REJECTED.format(
                    count = len(self.spill.rejected),
                    minimum = LIMITS.min_secret_length,
                )
            )

    def _muted(self, name: str) -> Alert:
        return Alert(
            check = name,
            rule = RULE_MUTED,
            weight = Weight.INFO,
            hard = False,
            evidence = "check muted by contract",
        )

    def _fault(self, name: str, error: Exception) -> Alert:
        return Alert(
            check = name,
            rule = RULE_FAULT,
            weight = Weight.CRITICAL,
            hard = True,
            evidence = type(error).__name__,
        )

    def _enabled(self, name: str) -> bool:
        return name in self.contract.checks

    def _run(self, name: str, envelope: Envelope) -> list[Alert]:
        if not self._enabled(name):
            return [self._muted(name)]

        try:
            return self.inbound[name].run(envelope, self.contract)
        except Exception as error:
            return [self._fault(name, error)]

    def inspect(self, envelope: Envelope) -> Outcome:
        """
        Inspect an envelope with every enabled check and resolve the
        alerts into a ruling
        """
        started = time.perf_counter()
        alerts: list[Alert] = []

        for name in INBOUND_CHECKS:
            alerts.extend(self._run(name, envelope))

        alerts = promote(alerts, self.contract)
        took_ms = (time.perf_counter() - started) * 1000.0

        return Outcome(
            ruling = resolve(alerts,
                             self.contract),
            alerts = tuple(alerts),
            contract_id = self.contract.contract_id,
            took_ms = took_ms,
        )

    def authorize(
        self,
        reply: Reply,
        envelope: Envelope,
    ) -> Outcome:
        """
        Grant what the model proposes only where the contract allows
        it, and refuse anything that would carry a secret out
        """
        started = time.perf_counter()
        alerts: list[Alert] = []

        alerts.extend(self._authorize_grants(reply, envelope))
        alerts.extend(self._inspect_spills(reply))

        took_ms = (time.perf_counter() - started) * 1000.0

        return Outcome(
            ruling = resolve(alerts,
                             self.contract),
            alerts = tuple(alerts),
            contract_id = self.contract.contract_id,
            took_ms = took_ms,
        )

    def _authorize_grants(
        self,
        reply: Reply,
        envelope: Envelope,
    ) -> list[Alert]:
        if not self._enabled(CHECK_GRANT):
            return [self._muted(CHECK_GRANT)]

        try:
            return self.grant.authorize(reply, envelope, self.contract)
        except Exception as error:
            return [self._fault(CHECK_GRANT, error)]

    def _inspect_spills(self, reply: Reply) -> list[Alert]:
        if not self._enabled(CHECK_SPILL):
            return [self._muted(CHECK_SPILL)]

        try:
            surfaces = outbound_surfaces(reply)
            budget = sum(len(surface) for surface in surfaces)

            if budget > LIMITS.max_reply_bytes:
                return [
                    Alert(
                        check = CHECK_SPILL,
                        rule = RULE_REPLY_TOO_LARGE,
                        weight = Weight.CRITICAL,
                        hard = True,
                        evidence = f"{budget} chars across the reply",
                    )
                ]

            alerts: list[Alert] = []
            for surface in surfaces:
                alerts.extend(self.spill.inspect(surface))
        except Exception as error:
            return [self._fault(CHECK_SPILL, error)]
        else:
            return alerts

    def compose(self, envelope: Envelope) -> str:
        """
        Build the fenced prompt for this envelope
        """
        return compose(envelope)
