#!/usr/bin/env python3
"""Parity anchor: attestra_packs.slot_settle_gate vs the real SlotSettleGate engine.

SlotSettleGate is an independent repo (github.com/sadpig70/SlotSettleGate); it is not
vendored in Attestra. When its source is importable in a dev checkout, this test asserts
the pack's verdict reproduces engine.evaluate_packet's verdict (authorized/review/vetoed)
across every branch of all three checks. In CI (source absent) it skips.

Point SLOTSETTLEGATE_SRC at the dir holding the SlotSettleGate package, e.g.
    SLOTSETTLEGATE_SRC=D:/recreate_prj/SlotSettleGate python -m unittest tests.test_slot_settle_gate_parity
"""

import os
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.slot_settle_gate import PREDICATES


def _load_engine():
    candidates = [os.environ.get("SLOTSETTLEGATE_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "SlotSettleGate"),
        "D:/recreate_prj/SlotSettleGate",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from SlotSettleGate.engine import evaluate_packet  # noqa: WPS433
        return evaluate_packet
    except Exception:  # noqa: BLE001 — source simply not present here
        return None


_EVAL = _load_engine()

_VERDICT_TO_ATTESTRA = {"authorized": "valid", "review": "thin", "vetoed": "breach"}

_HASH = "a" * 64
_SLOT_OK = {"slot_id": "s1", "slot_start_unix": 1000, "slot_end_unix": 2000,
            "execution_unix": 1400, "duration_limit_sec": 2000, "reauth_required": False,
            "reauth_granted": False, "authorization_hash": _HASH}
_SETTLE_OK = {"amount_usd": 100.0, "rules_passed": 10, "rules_total": 10,
              "compliance_score": 0.98, "jurisdiction": "US"}
_VETO_OK = {"risk_score": 0.2, "escrow_active": True, "veto_threshold": 0.8,
            "interrupt_requested": False}


def _p(slot=None, settle=None, veto=None):
    return {"slot": dict(slot or _SLOT_OK), "settlement": dict(settle or _SETTLE_OK),
            "veto_escrow": dict(veto or _VETO_OK)}

# Exercise each branch: clean; slot near-end review; slot vetoed; settlement partial
# review; settlement vetoed; compliance review; veto approaching review; veto vetoed;
# missing section.
_CASES = [
    _p(),
    _p(slot={**_SLOT_OK, "execution_unix": 1950, "reauth_required": True, "reauth_granted": True}),
    _p(slot={**_SLOT_OK, "execution_unix": 3000}),
    _p(settle={**_SETTLE_OK, "rules_passed": 8}),
    _p(settle={**_SETTLE_OK, "rules_passed": 5}),
    _p(settle={**_SETTLE_OK, "compliance_score": 0.90}),
    _p(veto={**_VETO_OK, "risk_score": 0.65}),
    _p(veto={**_VETO_OK, "risk_score": 0.9}),
    {"slot": _SLOT_OK, "settlement": _SETTLE_OK},  # missing veto_escrow -> vetoed
]


@unittest.skipUnless(_EVAL is not None, "SlotSettleGate source not importable (independent repo)")
class TestSlotSettleGateParity(unittest.TestCase):
    def test_verdict_matches_source(self):
        for i, sections in enumerate(_CASES):
            with self.subTest(case=i):
                src = _EVAL(sections)["verdict"]
                expected = _VERDICT_TO_ATTESTRA[src]
                packet = {"packet_id": "P", "subject": "P", **sections}
                result = run_gates(packet, PREDICATES, now="T")
                self.assertEqual(
                    result["verdict"], expected,
                    f"source={src} -> expected {expected}, got {result['verdict']} (worst={result.get('worst')})")


if __name__ == "__main__":
    unittest.main()
