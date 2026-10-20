"""
© https://github.com/YouFoundTheDev | 2026
residue.py
"""

from dataclasses import replace

from airlock.codec.peel import peel
from airlock.codec.surface import flatten
from airlock.contract import Contract
from airlock.envelope import Envelope, Provenance
from airlock.ruling import Alert
from airlock.settings import CHECK_RESIDUE


class ResidueCheck:
    """
    The pre-pass that makes text legible, reporting every transform it
    needed rather than deciding anything
    """

    name = CHECK_RESIDUE

    def run(
        self,
        envelope: Envelope,
        contract: Contract,
    ) -> list[Alert]:
        """
        Report the hiding places found in every segment the operator
        did not author
        """
        alerts: list[Alert] = []

        for index, segment in enumerate(envelope.segments):
            if segment.provenance is Provenance.INSTRUCTION:
                continue

            surface = flatten(segment.body)
            stripped = peel(surface.text)

            for alert in (*surface.alerts, *stripped.alerts):
                alerts.append(replace(alert, segment = index))

        return alerts
