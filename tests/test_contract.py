"""
© https://github.com/YouFoundTheDev | 2026
test_contract.py
"""

from airlock.contract import Contract, promote, resolve
from airlock.ruling import Alert, Ruling, Weight
from airlock.settings import (
    ALL_CHECKS,
    CHECK_RESIDUE,
    RULE_INSTRUCTIONAL,
    RULE_LOOKALIKE,
)


def _alert(
    weight: Weight,
    hard: bool,
    rule: str = "rule",
) -> Alert:
    return Alert(
        check = "test",
        rule = rule,
        weight = weight,
        hard = hard,
        segment = None,
        evidence = "",
    )


def test_hard_alert_forces_refusal_below_threshold() -> None:
    contract = Contract(threshold = Weight.CRITICAL)

    assert resolve([_alert(Weight.LOW,
                           hard = True)],
                   contract) is (Ruling.REFUSE)


def test_soft_alert_below_threshold_permits() -> None:
    contract = Contract(threshold = Weight.HIGH)

    assert resolve([_alert(Weight.MODERATE,
                           hard = False)],
                   contract) is (Ruling.PERMIT)


def test_soft_alert_at_threshold_refuses() -> None:
    contract = Contract(threshold = Weight.HIGH)

    assert resolve([_alert(Weight.HIGH,
                           hard = False)],
                   contract) is (Ruling.REFUSE)


def test_no_alerts_permits() -> None:
    assert resolve([], Contract()) is Ruling.PERMIT


def test_info_alerts_never_refuse() -> None:
    contract = Contract(threshold = Weight.INFO)

    assert resolve([_alert(Weight.INFO,
                           hard = False)],
                   contract) is (Ruling.PERMIT)


def test_strict_promotes_instructional_prose_to_hard() -> None:
    alerts = [
        _alert(Weight.MODERATE,
               hard = False,
               rule = RULE_INSTRUCTIONAL)
    ]

    promoted = promote(alerts, Contract(strict = True))

    assert promoted[0].hard is True
    assert resolve(promoted, Contract()) is Ruling.REFUSE


def test_lenient_leaves_instructional_prose_soft() -> None:
    alerts = [
        _alert(Weight.MODERATE,
               hard = False,
               rule = RULE_INSTRUCTIONAL)
    ]

    promoted = promote(alerts, Contract(strict = False))

    assert promoted[0].hard is False
    assert resolve(promoted, Contract()) is Ruling.PERMIT


def test_strict_does_not_promote_an_unrelated_rule() -> None:
    alerts = [_alert(Weight.MODERATE, hard = False, rule = RULE_LOOKALIKE)]

    assert promote(alerts, Contract(strict = True))[0].hard is False


def test_weight_is_ordered() -> None:
    assert Weight.INFO < Weight.LOW < Weight.MODERATE
    assert Weight.MODERATE < Weight.HIGH < Weight.CRITICAL


def test_without_removes_only_the_named_checks() -> None:
    contract = Contract().without(CHECK_RESIDUE)

    assert CHECK_RESIDUE not in contract.checks
    assert len(contract.checks) == len(ALL_CHECKS) - 1


def test_only_keeps_exactly_the_named_checks() -> None:
    contract = Contract().only(CHECK_RESIDUE)

    assert contract.checks == frozenset({CHECK_RESIDUE})


def test_holding_registers_one_secret() -> None:
    contract = Contract().holding("VANTAGE-7731-ORION")

    assert contract.secrets == ("VANTAGE-7731-ORION",
                                )


def test_the_original_contract_is_untouched_by_its_helpers() -> None:
    original = Contract()

    original.without(CHECK_RESIDUE)
    original.only(CHECK_RESIDUE)
    original.holding("VANTAGE-7731-ORION")

    assert original.checks == frozenset(ALL_CHECKS)
    assert original.secrets == ()
