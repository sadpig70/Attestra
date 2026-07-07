#!/usr/bin/env python3
"""Parity anchor: attestra_packs.settle_mesh vs the real SettleMesh screen.

SettleMesh is an independent repo (github.com/sadpig70/SettleMesh); it is not vendored in
Attestra. When its source is importable in a dev checkout, this test asserts the pack's
verdict reproduces screen.screen's verdict (clear/review/block) across intents tripping
each of the four rules. In CI (source absent) it skips.

Point SETTLEMESH_SRC at the project's ``src`` dir to run it, e.g.
    SETTLEMESH_SRC=D:/IdeaFirst/settlemesh/src python -m unittest tests.test_settle_mesh_parity
"""

import os
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.settle_mesh import PREDICATES


def _load_settlemesh():
    candidates = [os.environ.get("SETTLEMESH_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "settlemesh", "src"),
        os.path.join(here, "..", "SettleMesh", "src"),
        "D:/IdeaFirst/settlemesh/src",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from settlemesh import screen as screen_mod  # noqa: WPS433
        from settlemesh import models as models_mod  # noqa: WPS433
        return screen_mod, models_mod
    except Exception:  # noqa: BLE001 — source simply not present here
        return None, None


_SCREEN, _MODELS = _load_settlemesh()

_VERDICT_TO_ATTESTRA = {"clear": "valid", "review": "thin", "block": "breach"}


def _intent(**kw):
    base = {"intent_id": "i", "asset": "usdc", "amount": 500.0, "sender": "alice", "receiver": "bob",
            "sender_jurisdiction": "US", "receiver_jurisdiction": "EU", "sender_kyc_tier": 1,
            "purpose": "general"}
    base.update(kw)
    return base

# Intents tripping each rule: clean; under-reserved; sanctioned; high-risk purpose;
# blocked corridor; restricted corridor; over tier-0 limit (block); over tier-1 limit (review).
_CASES = [
    _intent(),
    _intent(asset="demo_undercollateralized"),
    _intent(receiver="ofac-demo-001"),
    _intent(purpose="mixing"),
    _intent(sender_jurisdiction="US", receiver_jurisdiction="KP"),
    _intent(sender_jurisdiction="US", receiver_jurisdiction="XX"),
    _intent(sender_kyc_tier=0, amount=5000.0),
    _intent(sender_kyc_tier=1, amount=50000.0),
]


@unittest.skipUnless(_SCREEN is not None, "SettleMesh source not importable (independent repo)")
class TestSettleMeshParity(unittest.TestCase):
    def test_verdict_matches_source(self):
        for intent in _CASES:
            with self.subTest(intent=intent):
                src = _SCREEN.screen(_MODELS.SettlementIntent.from_dict(intent)).verdict
                expected = _VERDICT_TO_ATTESTRA[src]
                result = run_gates({"packet_id": "P", "subject": "P", "intent": intent}, PREDICATES, now="T")
                self.assertEqual(
                    result["verdict"], expected,
                    f"source={src} -> expected {expected}, got {result['verdict']} (worst={result.get('worst')})")


if __name__ == "__main__":
    unittest.main()
