#!/usr/bin/env python3
"""Parity anchor: attestra_packs.cover_gate vs the real CoverGate reference.

CoverGate is an independent repo (github.com/sadpig70/CoverGate); it is not vendored in
Attestra. When its source is importable in a dev checkout, this test asserts the pack's
verdict reproduces CoverGate's underwriting decision (covered/referred/declined) exactly
across requests spanning every branch. In CI (source absent) it skips.

Point COVERGATE_SRC at the project's ``src`` dir to run it, e.g.
    COVERGATE_SRC=D:/IdeaFirst/covergate/src python -m unittest tests.test_cover_gate_parity
"""

import os
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.cover_gate import PREDICATES


def _load_covergate():
    candidates = [os.environ.get("COVERGATE_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "covergate", "src"),
        os.path.join(here, "..", "CoverGate", "src"),
        "D:/IdeaFirst/covergate/src",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from covergate import engine as engine_mod  # noqa: WPS433
        from covergate import models as models_mod  # noqa: WPS433
        return engine_mod, models_mod
    except Exception:  # noqa: BLE001 — source simply not present here
        return None, None


_ENGINE, _MODELS = _load_covergate()

# CoverGate decision -> Attestra verdict.
_DECISION_TO_VERDICT = {"covered": "valid", "referred": "thin", "declined": "breach"}

# Requests exercising every branch (covered / referred / declined) + provenance penalty.
_CASES = [
    {"design_id": "a", "requester_reputation": 0.9, "novelty_distance": 0.1,
     "concern_sequence_hits": 0, "submission_velocity": 0.1, "tool_provenance_verified": True,
     "exposure_value": 1000.0},
    {"design_id": "b", "requester_reputation": 0.1, "novelty_distance": 0.9,
     "concern_sequence_hits": 3, "submission_velocity": 0.5, "tool_provenance_verified": True,
     "exposure_value": 1000.0},
    {"design_id": "c", "requester_reputation": 0.0, "novelty_distance": 1.0,
     "concern_sequence_hits": 5, "submission_velocity": 1.0, "tool_provenance_verified": False,
     "exposure_value": 1000.0},
    {"design_id": "d", "requester_reputation": 0.6, "novelty_distance": 0.5,
     "concern_sequence_hits": 1, "submission_velocity": 0.2, "tool_provenance_verified": False,
     "exposure_value": 500.0},
]


def _packet(req):
    return {"packet_id": req["design_id"], "subject": req["design_id"], "request": req}


@unittest.skipUnless(_ENGINE is not None, "CoverGate source not importable (independent repo)")
class TestCoverGateParity(unittest.TestCase):
    def test_decision_matches_source(self):
        policy = _MODELS.UnderwritingPolicy()
        for req in _CASES:
            with self.subTest(design=req["design_id"]):
                finding = _ENGINE.underwrite_one(policy, _MODELS.DesignRequest.from_dict(req))
                expected = _DECISION_TO_VERDICT[finding.decision]

                result = run_gates(_packet(req), PREDICATES, now="T")
                self.assertEqual(
                    result["verdict"], expected,
                    f"decision={finding.decision} -> expected {expected}, got {result['verdict']}")


if __name__ == "__main__":
    unittest.main()
