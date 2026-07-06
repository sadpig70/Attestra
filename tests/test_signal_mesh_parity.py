#!/usr/bin/env python3
"""Parity anchor: attestra_packs.signal_mesh vs the real SignalMesh reference.

SignalMesh is an independent repo (github.com/sadpig70/SignalMesh); it is not vendored
in Attestra. When its source is importable in a dev checkout, this test asserts the
pack's aggregate verdict reproduces SignalMesh's exchange posture exactly across a
battery of batches (the interesting cases: all tradeable, a single blocked stream
alongside tradeable ones, zero tradeable). In CI (source absent) it skips.

Point SIGNALMESH_SRC at the project's ``src`` dir to run it, e.g.
    SIGNALMESH_SRC=D:/IdeaFirst/signalmesh/src python -m unittest tests.test_signal_mesh_parity
"""

import os
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.signal_mesh import PREDICATES


def _load_signalmesh():
    candidates = [os.environ.get("SIGNALMESH_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "signalmesh", "src"),
        os.path.join(here, "..", "SignalMesh", "src"),
        "D:/IdeaFirst/signalmesh/src",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from signalmesh import mine as mine_mod  # noqa: WPS433
        from signalmesh import models as models_mod  # noqa: WPS433
        return mine_mod, models_mod
    except Exception:  # noqa: BLE001 — source simply not present here
        return None, None


_MINE, _MODELS = _load_signalmesh()

# SignalMesh exchange posture -> Attestra verdict.
_POSTURE_TO_VERDICT = {"exchange_ready": "valid", "conditional": "thin", "blocked": "breach"}


def _batch(streams, policy=None):
    return {"policy": policy or {}, "streams": streams}


def _packet(streams, policy=None):
    return {"packet_id": "P", "subject": "P",
            "policy": policy or {"block_pii": True, "require_consent_for_restricted": True,
                                 "min_quality": 0.5},
            "streams": streams}


def _st(sid, et, sens, vol=100.0, q=0.9, consent=False):
    return {"stream_id": sid, "exhaust_type": et, "sensitivity": sens,
            "volume": vol, "quality": q, "consent_obtained": consent}


# Batches exercising every posture branch, incl. the non-max-severity edge.
_CASES = [
    [_st("s1", "logs", "public"), _st("s2", "latency_traces", "internal")],          # all tradeable
    [_st("s1", "logs", "public"), _st("s2", "disputes", "restricted")],              # one restricted
    [_st("s1", "compliance_traces", "pii"), _st("s2", "disputes", "restricted")],    # zero tradeable
    [_st("s1", "logs", "public"), _st("s2", "error_traces", "pii")],                 # blocked + tradeable -> conditional
    [_st("s1", "disputes", "restricted", consent=True)],                             # consented restricted -> tradeable
    [_st("s1", "logs", "public", q=0.1)],                                            # low quality -> restricted -> no tradeable
]


@unittest.skipUnless(_MINE is not None, "SignalMesh source not importable (independent repo)")
class TestSignalMeshParity(unittest.TestCase):
    def test_posture_matches_source(self):
        for streams in _CASES:
            with self.subTest(streams=[s["stream_id"] + ":" + s["sensitivity"] for s in streams]):
                sm_streams = [_MODELS.ExhaustStream.from_dict(s) for s in streams]
                sm_policy = _MODELS.SignalPolicy.from_dict({})
                posture = _MINE.mine(sm_policy, sm_streams).posture.verdict
                expected = _POSTURE_TO_VERDICT[posture]

                result = run_gates(_packet(streams), PREDICATES, now="T")
                self.assertEqual(
                    result["verdict"], expected,
                    f"posture={posture} -> expected {expected}, got {result['verdict']} "
                    f"(worst={result.get('worst')})")


if __name__ == "__main__":
    unittest.main()
