#!/usr/bin/env python3
"""Parity anchor: attestra_packs.spend_mesh vs the real SpendMesh reference.

SpendMesh is an independent repo (github.com/sadpig70/SpendMesh); it is not vendored in
Attestra. When its source is importable in a dev checkout, this test asserts the pack's
verdict reproduces SpendMesh.evaluate's verdict (approve/review/deny) across requests
that trip each of the six controls. In CI (source absent) it skips.

Point SPENDMESH_SRC at the project's ``src`` dir to run it, e.g.
    SPENDMESH_SRC=D:/IdeaFirst/spendmesh/src python -m unittest tests.test_spend_mesh_parity
"""

import os
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.spend_mesh import PREDICATES


def _load_spendmesh():
    candidates = [os.environ.get("SPENDMESH_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "spendmesh", "src"),
        os.path.join(here, "..", "SpendMesh", "src"),
        "D:/IdeaFirst/spendmesh/src",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from spendmesh import evaluate as evaluate_mod  # noqa: WPS433
        from spendmesh import models as models_mod  # noqa: WPS433
        return evaluate_mod, models_mod
    except Exception:  # noqa: BLE001 — source simply not present here
        return None, None


_EVAL, _MODELS = _load_spendmesh()

_VERDICT_TO_ATTESTRA = {"approve": "valid", "review": "thin", "deny": "breach"}

# (policy, request) pairs tripping each control: clean, approval-review, budget-deny,
# category-review, category-deny, rate-deny, vendor-deny, vendor-review, transaction-deny.
_CASES = [
    ({"total_budget": 10000, "spent_to_date": 0},
     {"request_id": "r", "agent_id": "a", "amount": 100, "category": "c", "vendor": "v"}),
    ({"total_budget": 10000, "approval_threshold": 50},
     {"request_id": "r", "agent_id": "a", "amount": 100, "category": "c", "vendor": "v"}),
    ({"total_budget": 100},
     {"request_id": "r", "agent_id": "a", "amount": 500, "category": "c", "vendor": "v"}),
    ({"total_budget": 10000, "category_limits": {"travel": 200}},
     {"request_id": "r", "agent_id": "a", "amount": 50, "category": "unknown", "vendor": "v"}),
    ({"total_budget": 10000, "category_limits": {"travel": 200}},
     {"request_id": "r", "agent_id": "a", "amount": 500, "category": "travel", "vendor": "v"}),
    ({"total_budget": 10000, "rate_limit_amount": 300},
     {"request_id": "r", "agent_id": "a", "amount": 200, "category": "c", "vendor": "v", "window_spend_to_date": 200}),
    ({"total_budget": 10000, "blocked_vendors": ["evilcorp"]},
     {"request_id": "r", "agent_id": "a", "amount": 100, "category": "c", "vendor": "evilcorp"}),
    ({"total_budget": 10000, "allowed_vendors": ["acme"]},
     {"request_id": "r", "agent_id": "a", "amount": 100, "category": "c", "vendor": "other"}),
    ({"total_budget": 10000, "per_transaction_limit": 50},
     {"request_id": "r", "agent_id": "a", "amount": 100, "category": "c", "vendor": "v"}),
]


def _packet(policy, request):
    return {"packet_id": "P", "subject": "P", "policy": policy, "request": request}


@unittest.skipUnless(_EVAL is not None, "SpendMesh source not importable (independent repo)")
class TestSpendMeshParity(unittest.TestCase):
    def test_verdict_matches_source(self):
        for policy, request in _CASES:
            with self.subTest(request=request):
                src = _EVAL.evaluate(_MODELS.TreasuryPolicy.from_dict({"agent_id": "a", **policy}),
                                     _MODELS.SpendRequest.from_dict(request)).verdict
                expected = _VERDICT_TO_ATTESTRA[src]
                result = run_gates(_packet(policy, request), PREDICATES, now="T")
                self.assertEqual(
                    result["verdict"], expected,
                    f"source={src} -> expected {expected}, got {result['verdict']} (worst={result.get('worst')})")


if __name__ == "__main__":
    unittest.main()
