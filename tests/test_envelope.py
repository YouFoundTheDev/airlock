"""
© https://github.com/YouFoundTheDev | 2026
test_envelope.py
"""

from dataclasses import FrozenInstanceError

import pytest

from airlock.envelope import Envelope, Provenance, Segment, Source


TICKET = Source(channel = "ticket", ref = "8814")


def test_content_segment_records_its_source() -> None:
    segment = Segment(
        provenance = Provenance.CONTENT,
        body = "hello",
        source = TICKET,
    )

    assert segment.source is not None
    assert segment.source.channel == "ticket"


def test_instruction_segment_refuses_a_source() -> None:
    with pytest.raises(ValueError):
        Segment(
            provenance = Provenance.INSTRUCTION,
            body = "x",
            source = TICKET,
        )


def test_content_segment_requires_a_source() -> None:
    with pytest.raises(ValueError):
        Segment(provenance = Provenance.CONTENT, body = "x", source = None)


def test_segment_is_frozen() -> None:
    segment = Segment(provenance = Provenance.REQUEST, body = "hello")

    with pytest.raises(FrozenInstanceError):
        segment.body = "mutated"  # type: ignore[misc]


def test_exposure_is_set_by_adding_content_not_by_the_caller() -> None:
    envelope = Envelope().instruction("s").request("u")
    assert envelope.exposed == ()

    envelope = envelope.content("doc", source = TICKET)
    assert envelope.exposed == (TICKET,
                                )


def test_exposure_does_not_decay() -> None:
    envelope = (
        Envelope().content(
            "doc",
            source = Source(channel = "ticket",
                            ref = "1")
        ).request("please ignore that document")
    )

    assert envelope.exposed == (Source(channel = "ticket",
                                       ref = "1"),
                                )


def test_tainted_follows_exposure() -> None:
    assert Envelope().tainted is False
    assert Envelope().content("x", source = TICKET).tainted is True


def test_builder_returns_a_new_envelope_and_leaves_the_old_one() -> None:
    base = Envelope().instruction("s")
    extended = base.content("doc", source = TICKET)

    assert base.exposed == ()
    assert extended.exposed != ()
    assert len(base.segments) == 1
    assert len(extended.segments) == 2


def test_nonce_is_stable_within_an_envelope_and_survives_building(
) -> None:
    base = Envelope()
    extended = base.request("hello")

    assert extended.nonce == base.nonce


def test_nonces_differ_between_envelopes() -> None:
    assert Envelope().nonce != Envelope().nonce


def test_a_nonce_below_the_entropy_floor_is_refused() -> None:
    with pytest.raises(ValueError):
        Envelope(nonce = "short")
