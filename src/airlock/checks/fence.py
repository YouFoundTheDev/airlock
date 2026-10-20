"""
© https://github.com/YouFoundTheDev | 2026
fence.py
"""

from airlock.codec.spectrum import alnum_only, spectrum
from airlock.contract import Contract
from airlock.envelope import Envelope, Provenance
from airlock.ruling import Alert, Weight
from airlock.settings import CHECK_FENCE, LIMITS, RULE_FENCE_FORGED


class FenceCheck:
    """
    The boundary between content and instruction, enforced by a
    delimiter the content cannot predict
    """

    name = CHECK_FENCE

    def run(
        self,
        envelope: Envelope,
        contract: Contract,
    ) -> list[Alert]:
        """
        Refuse any external segment carrying this envelope's fence
        nonce, which it has no legitimate way to know
        """
        alerts: list[Alert] = []
        needle = alnum_only(envelope.nonce).casefold()

        for index, segment in enumerate(envelope.segments):
            if segment.provenance is not Provenance.CONTENT:
                continue
            if self._carries(segment.body, needle):
                alerts.append(
                    Alert(
                        check = CHECK_FENCE,
                        rule = RULE_FENCE_FORGED,
                        weight = Weight.CRITICAL,
                        hard = True,
                        segment = index,
                        evidence = "fence nonce present in content",
                    )
                )

        return alerts

    def _carries(self, body: str, needle: str) -> bool:
        return any(
            needle in alnum_only(reading).casefold()
            for reading in spectrum(body, LIMITS.max_text_variants)
        )
