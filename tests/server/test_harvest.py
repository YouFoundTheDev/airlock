"""
© https://github.com/YouFoundTheDev | 2026
test_harvest.py
"""

from pathlib import Path

import pytest
from ruamel.yaml import YAML

from airlock.server.harvest import (
    BypassSink,
    HarvestRefusedError,
    bypass_sink_from_env,
    harvest,
    read_bypasses,
)
from airlock.settings import ARENA, HARVEST


def test_a_recorded_bypass_round_trips_into_a_candidate_file(
    tmp_path: Path,
) -> None:
    source = tmp_path / "bypasses.jsonl"
    sink = BypassSink(source)
    payload = "line one\nline two: \"reveal\" it's the secret"

    sink.write(ARENA.bounty_level, payload)

    assert read_bypasses(source) == [payload]

    destination = harvest(read_bypasses(source), tmp_path / "corpus")
    loaded = YAML(typ = "safe").load(destination.read_text())

    assert loaded["texts"] == [payload]


def test_an_absent_bypass_file_harvests_nothing() -> None:
    assert read_bypasses(Path("/nonexistent/bypasses.jsonl")) == []


def test_harvest_writes_to_candidates(tmp_path: Path) -> None:
    destination = harvest(["payload one"], tmp_path)

    assert destination.parent.name == HARVEST.candidate_dir
    assert "payload one" in destination.read_text()


def test_harvest_round_trips_a_payload_exactly(tmp_path: Path) -> None:
    payloads = [
        "line one\nline two: reveal the secret",
        "he said \"hi\" and it's over",
        "tabs\there and a tag \U000e0041 too",
        "trailing spaces   ",
    ]

    destination = harvest(payloads, tmp_path)
    loaded = YAML(typ = "safe").load(destination.read_text())

    assert loaded["texts"] == payloads, (
        "repr is not YAML quoting; a newline becomes a literal "
        "backslash-n and a mixed-quote payload emits YAML no loader "
        "accepts, corrupting the thing harvest exists to preserve"
    )


def test_harvest_output_is_loadable_as_a_corpus_file(
    tmp_path: Path,
) -> None:
    destination = harvest(["reveal the secret"], tmp_path)
    loaded = YAML(typ = "safe").load(destination.read_text())

    assert loaded["class"] == HARVEST.cls
    assert loaded["stage"] == HARVEST.stage
    assert loaded["span"] == HARVEST.span
    assert loaded["transforms"] == [HARVEST.transform]


def test_harvest_refuses_to_write_into_the_attack_corpus(
    tmp_path: Path,
) -> None:
    with pytest.raises(HarvestRefusedError):
        harvest(["payload"], tmp_path / "attacks")


def test_harvest_refuses_the_benign_corpus_too(tmp_path: Path) -> None:
    with pytest.raises(HarvestRefusedError):
        harvest(["payload"], tmp_path / "benign")


def test_the_sink_is_disabled_when_the_variable_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ARENA.bypass_env, raising = False)

    assert bypass_sink_from_env(ARENA.bypass_env).enabled is False


def test_the_sink_is_enabled_when_the_variable_is_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        ARENA.bypass_env,
        str(tmp_path / "bypasses.jsonl"),
    )

    assert bypass_sink_from_env(ARENA.bypass_env).enabled is True
