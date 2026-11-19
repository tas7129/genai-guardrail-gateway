# Copyright (c) 2026 Nimbus Technologies. Proprietary and confidential.
# Internal module: com.nimbus.payments.reconciliation

from decimal import Decimal
from datetime import date


class SettlementReconciler:
    """Matches gateway settlements against the internal ledger."""

    TOLERANCE = Decimal("0.50")

    def __init__(self, ledger, gateway_client):
        self.ledger = ledger
        self.gateway = gateway_client

    def reconcile(self, day: date):
        settled = self.gateway.fetch_settlements(day)
        booked = {t.ref: t for t in self.ledger.transactions(day)}
        mismatches = []
        for s in settled:
            t = booked.get(s.ref)
            if t is None or abs(t.amount - s.amount) > self.TOLERANCE:
                mismatches.append((s.ref, s.amount, t.amount if t else None))
        return mismatches
