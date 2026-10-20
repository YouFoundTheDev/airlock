"""
© https://github.com/YouFoundTheDev | 2026
grant.py
"""

from collections.abc import Iterable, Mapping

from pydantic import ValidationError

from airlock.capability import Capability, Proposal, Requirement, Reply
from airlock.contract import Contract
from airlock.envelope import Envelope
from airlock.ruling import Alert, Weight
from airlock.settings import (
    CHECK_GRANT,
    RULE_ARGS_INVALID,
    RULE_ARGS_NOT_ALLOWLISTED,
    RULE_ARGS_UNEXPECTED,
    RULE_IMPACT_DENIED,
    RULE_TAINTED,
    RULE_UNCONFIRMED,
    RULE_UNKNOWN_CAPABILITY,
)


class GrantCheck:
    """
    The model proposes an action and this decides whether it happens,
    without ever consulting the model's stated reason
    """

    name = CHECK_GRANT

    def __init__(self, registry: Mapping[str, Capability]) -> None:
        self.registry = dict(registry)

    def _alert(self, rule: str, evidence: str) -> Alert:
        return Alert(
            check = CHECK_GRANT,
            rule = rule,
            weight = Weight.CRITICAL,
            hard = True,
            evidence = evidence,
        )

    def authorize(
        self,
        reply: Reply,
        envelope: Envelope,
        contract: Contract,
    ) -> list[Alert]:
        """
        Authorize every proposal in a reply against the registry and
        the exposure the envelope has already picked up
        """
        alerts: list[Alert] = []

        for proposal in reply.proposals:
            alerts.extend(
                self._authorize_one(proposal,
                                    envelope,
                                    contract)
            )

        return alerts

    def _authorize_one(
        self,
        proposal: Proposal,
        envelope: Envelope,
        contract: Contract,
    ) -> list[Alert]:
        capability = self.registry.get(proposal.name)
        if capability is None:
            return [
                self._alert(RULE_UNKNOWN_CAPABILITY,
                            proposal.name),
            ]

        return [
            *self._impact_alerts(capability,
                                 contract),
            *self._argument_alerts(capability,
                                   proposal),
            *self._requirement_alerts(capability,
                                      proposal,
                                      envelope),
        ]

    def _impact_alerts(
        self,
        capability: Capability,
        contract: Contract,
    ) -> Iterable[Alert]:
        denied = capability.impacts & contract.denied_impacts
        if denied:
            yield self._alert(
                RULE_IMPACT_DENIED,
                f"{capability.name} carries {sorted(denied)}",
            )

    def _argument_alerts(
        self,
        capability: Capability,
        proposal: Proposal,
    ) -> Iterable[Alert]:
        missing = capability.required_args - proposal.args.keys()
        if missing:
            yield self._alert(
                RULE_ARGS_INVALID,
                f"{capability.name} missing {sorted(missing)}",
            )

        unexpected = proposal.args.keys() - capability.accepted_args
        if unexpected:
            yield self._alert(
                RULE_ARGS_UNEXPECTED,
                f"{capability.name} unexpected {sorted(unexpected)}",
            )

        yield from self._schema_alerts(capability, proposal)

    def _schema_alerts(
        self,
        capability: Capability,
        proposal: Proposal,
    ) -> Iterable[Alert]:
        if capability.arg_schema is None:
            return

        try:
            capability.arg_schema.model_validate(proposal.args)
        except ValidationError as invalid:
            yield self._alert(
                RULE_ARGS_INVALID,
                f"{capability.name} failed schema with "
                f"{invalid.error_count()} error(s)",
            )

    def _requirement_alerts(
        self,
        capability: Capability,
        proposal: Proposal,
        envelope: Envelope,
    ) -> Iterable[Alert]:
        if (Requirement.UNTAINTED in capability.requirements
                and envelope.exposed):
            origins = ",".join(
                f"{source.channel}:{source.ref}"
                for source in envelope.exposed
            )
            yield self._alert(
                RULE_TAINTED,
                f"{capability.name} downstream of {origins}",
            )

        if (Requirement.CONFIRMED in capability.requirements
                and not proposal.confirmed):
            yield self._alert(
                RULE_UNCONFIRMED,
                f"{capability.name} requires explicit confirmation",
            )

        if Requirement.ALLOWLISTED in capability.requirements:
            for key, allowed in capability.allowlist.items():
                value = proposal.args.get(key)
                if not isinstance(value, str) or value not in allowed:
                    yield self._alert(
                        RULE_ARGS_NOT_ALLOWLISTED,
                        f"{capability.name}.{key}",
                    )
