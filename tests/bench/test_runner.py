"""
© https://github.com/YouFoundTheDev | 2026
test_runner.py
"""

import pytest

from airlock.envelope import Provenance
from airlock.settings import ALL_CHECKS
from bench.runner import (
    Ablation,
    Report,
    base_contract,
    format_report,
    load_corpus,
    run,
    run_ablation,
)


MIN_PER_CLASS = 10

MAX_FALSE_POSITIVE_RATE = 0.05

MAX_HARD_FALSE_POSITIVE_RATE = 0.05

MIN_DETECTION_RATE = 0.90

HARD_BENIGN_CLASS = "benign_adversarial_data"

REQUEST_BENIGN_CLASS = "benign_adversarial_user"


@pytest.fixture(scope = "module")
def report() -> Report:
    return run()


@pytest.fixture(scope = "module")
def ablation() -> dict[str, Ablation]:
    return run_ablation()


def test_the_corpus_has_both_halves() -> None:
    attacks, benign = load_corpus()

    assert attacks
    assert benign, "a detector with no benign corpus always says yes"


def test_every_class_has_enough_cases() -> None:
    attacks, benign = load_corpus()
    counts: dict[str, int] = {}
    for case in (*attacks, *benign):
        counts[case.label] = counts.get(case.label, 0) + 1

    thin = {
        label: count
        for label, count in counts.items()
        if count < MIN_PER_CLASS
    }

    assert thin == {}, f"classes too small to mean anything: {thin}"


def test_the_benign_corpus_covers_both_segment_kinds() -> None:
    _, benign = load_corpus()
    labels = {case.label for case in benign}

    assert REQUEST_BENIGN_CLASS in labels
    assert HARD_BENIGN_CLASS in labels


def test_the_hard_benign_class_sits_where_phrasing_actually_runs() -> None:
    _, benign = load_corpus()
    hard = [case for case in benign if case.label == HARD_BENIGN_CLASS]

    assert hard
    assert all(case.span == Provenance.CONTENT for case in hard), (
        "phrasing skips every segment that is not external content, so "
        "an adversarially-benign class in a request segment measures a "
        "`continue` statement and always reports 0.0%"
    )


def test_the_request_benign_class_proves_the_scoping() -> None:
    _, benign = load_corpus()
    requests = [
        case for case in benign if case.label == REQUEST_BENIGN_CLASS
    ]

    assert requests
    assert all(case.span == Provenance.REQUEST for case in requests)


def test_every_check_is_load_bearing(
    ablation: dict[str,
                   Ablation]
) -> None:
    inert = [check for check, result in ablation.items() if result.inert]

    assert inert == [], f"inert checks must be deleted, not tolerated: {inert}"


def test_the_ablation_covers_every_check(
    ablation: dict[str,
                   Ablation],
) -> None:
    assert set(ablation) == set(ALL_CHECKS)


def test_alibied_checks_are_reported_not_hidden(
    ablation: dict[str,
                   Ablation],
) -> None:
    alibied = [
        check for check, result in ablation.items() if result.alibied
    ]

    for check in alibied:
        assert ablation[check].solo > 0


def test_the_false_positive_rate_is_reported_and_low(
    report: Report
) -> None:
    assert report.false_positive_rate <= MAX_FALSE_POSITIVE_RATE


def test_the_hard_benign_class_has_its_own_floor(report: Report) -> None:
    rate = report.class_false_positive_rate(HARD_BENIGN_CLASS)

    assert rate <= MAX_HARD_FALSE_POSITIVE_RATE, (
        f"legitimate retrieved content refuses at {rate * 100:.1f}%; "
        "the pooled rate hides this because three benign classes are "
        "easy"
    )


def test_the_detection_rate_meets_the_floor(report: Report) -> None:
    assert report.detection_rate >= MIN_DETECTION_RATE


def test_the_report_states_who_wrote_the_corpus(
    report: Report,
    ablation: dict[str,
                   Ablation],
) -> None:
    text = format_report(report, ablation)

    assert "written by the same author as the rules" in text
    assert "false positive rate" in text


def test_the_report_separates_the_hard_benign_rate_from_the_pooled_one(
    report: Report,
    ablation: dict[str,
                   Ablation],
) -> None:
    text = format_report(report, ablation)

    assert "FPR on hard benign" in text
    assert HARD_BENIGN_CLASS in text


def test_disabling_everything_catches_nothing() -> None:
    naked = run(base_contract(checks = frozenset()))

    assert naked.detection_rate == 0.0
