#!/usr/bin/env python3
"""Parity anchor: attestra_packs.afferent_interrupt vs the real AfferentInterrupt engine.

AfferentInterrupt is an independent repo (github.com/sadpig70/AfferentInterrupt); it is
not vendored in Attestra. When its source is importable in a dev checkout, this test
asserts the pack's verdict reproduces AfferentInterruptEngine's determine_verdict across
every branch (cleared / intercepted / breached). In CI (source absent) it skips.

Point AFFERENTINTERRUPT_SRC at the dir holding afferent_interrupt.py, e.g.
    AFFERENTINTERRUPT_SRC=D:/recreate_prj/AfferentInterrupt python -m unittest tests.test_afferent_interrupt_parity
"""

import os
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.afferent_interrupt import PREDICATES


def _load_engine():
    candidates = [os.environ.get("AFFERENTINTERRUPT_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "AfferentInterrupt"),
        "D:/recreate_prj/AfferentInterrupt",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from afferent_interrupt import AfferentInterruptEngine  # noqa: WPS433
        return AfferentInterruptEngine
    except Exception:  # noqa: BLE001 — source simply not present here
        return None


_ENGINE = _load_engine()

_VERDICT_TO_ATTESTRA = {"cleared": "valid", "intercepted": "thin", "breached": "breach"}


def _step(step, state, action, cost=1.0, checked=True):
    return {"step": step, "state": state, "action": action,
            "resource_cost": cost, "safety_checked": checked}

# Traces exercising each branch: no-loop, runaway-loop, safety-breach, and a
# detected-but-low-score loop (stays cleared).
_CASES = [
    ([_step(1, "a", "x"), _step(2, "b", "y"), _step(3, "c", "z")], []),
    ([_step(1, "l", "r", 3.0), _step(2, "l", "r", 3.0), _step(3, "l", "r", 3.0), _step(4, "l", "r", 3.0)], []),
    ([_step(1, "a", "x"), _step(2, "b", "delete_all")], ["delete_all"]),
    ([_step(1, "l", "r", 0.0), _step(2, "l", "r", 0.0), _step(3, "l", "r", 0.0)], []),
    ([_step(1, "a", "x", checked=False)], []),
]


def _packet(trace, policies):
    return {"packet_id": "P", "subject": "P", "trace": trace, "safety_policies": policies}


@unittest.skipUnless(_ENGINE is not None, "AfferentInterrupt source not importable (independent repo)")
class TestAfferentInterruptParity(unittest.TestCase):
    def test_verdict_matches_source(self):
        engine = _ENGINE()
        for trace, policies in _CASES:
            with self.subTest(trace=[s["action"] for s in trace], policies=policies):
                loop = engine.detect_trace_loop(trace)
                breach_flag = engine.assess_safety_rule(trace, policies)
                score = engine.compute_loop_score(loop, trace)
                src_verdict = engine.determine_verdict(score, breach_flag, loop)["verdict"]
                expected = _VERDICT_TO_ATTESTRA[src_verdict]

                result = run_gates(_packet(trace, policies), PREDICATES, now="T")
                self.assertEqual(
                    result["verdict"], expected,
                    f"source={src_verdict} -> expected {expected}, got {result['verdict']}")


if __name__ == "__main__":
    unittest.main()
