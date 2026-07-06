#!/usr/bin/env python3
"""Parity anchor: attestra_packs.afferent_core vs the real AfferentCore reference.

AfferentCore is an independent repo (github.com/sadpig70/AfferentCore); it is not
vendored in Attestra. When its source is importable in a dev checkout, this test asserts
the pack's verdict reproduces AfferentCore.reflex.verify_reflex's status across every
branch (covered / marginal / missed / sub_threshold / unsignalled). In CI it skips.

Point AFFERENTCORE_SRC at the project's ``src`` dir to run it, e.g.
    AFFERENTCORE_SRC=D:/IdeaFirst/afferentcore/src python -m unittest tests.test_afferent_core_parity
"""

import os
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.afferent_core import PREDICATES


def _load_afferentcore():
    candidates = [os.environ.get("AFFERENTCORE_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "afferentcore", "src"),
        os.path.join(here, "..", "AfferentCore", "src"),
        "D:/IdeaFirst/afferentcore/src",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from afferentcore import reflex as reflex_mod  # noqa: WPS433
        from afferentcore import models as models_mod  # noqa: WPS433
        return reflex_mod, models_mod
    except Exception:  # noqa: BLE001 — source simply not present here
        return None, None


_REFLEX, _MODELS = _load_afferentcore()

# AfferentCore reflex status -> Attestra verdict (pack's documented mapping).
_STATUS_TO_VERDICT = {
    "reflex_covered": "valid", "sub_threshold": "valid",
    "marginal": "thin",
    "reflex_missed": "breach", "unsignalled": "breach",
}

# (risk, irrev, commit_delay, signal_present, transmit, perception, reflex) per branch.
_CASES = [
    (0.9, 0.8, 400.0, True, 20.0, 30.0, 100.0),   # margin 200 -> reflex_covered
    (0.9, 0.8, 250.0, True, 20.0, 30.0, 100.0),   # margin 50  -> marginal
    (0.9, 0.8, 150.0, True, 20.0, 30.0, 100.0),   # margin -50 -> reflex_missed
    (0.1, 0.1, 300.0, True, 20.0, 30.0, 100.0),   # severity 0.1 < 0.2 -> sub_threshold
    (0.9, 0.8, 400.0, False, 0.0, 0.0, 100.0),    # no signal -> unsignalled
]


def _packet(risk, irrev, commit, present, transmit, perception, reflex):
    return {"packet_id": "P", "subject": "P",
            "event": {"event_id": "e", "risk": risk, "irreversibility": irrev, "commit_delay_ms": commit},
            "signal": ({"transmit_latency_ms": transmit, "perception_latency_ms": perception}
                       if present else None),
            "operator": {"reflex_latency_ms": reflex}}


@unittest.skipUnless(_REFLEX is not None, "AfferentCore source not importable (independent repo)")
class TestAfferentCoreParity(unittest.TestCase):
    def test_status_matches_source(self):
        for risk, irrev, commit, present, transmit, perception, reflex in _CASES:
            with self.subTest(commit=commit, present=present, risk=risk):
                event = _MODELS.ActionEvent(
                    event_id="e", agent_id="a", action_class="c", operator_id="op",
                    risk=risk, irreversibility=irrev, commit_delay_ms=commit, timestamp="")
                operator = _MODELS.Operator(operator_id="op", reflex_latency_ms=reflex,
                                            channel_ids=["ch"], timestamp="")
                signal = None
                if present:
                    signal = _MODELS.AfferentSignal(
                        event_id="e", operator_id="op", signal_class="soft_pulse", channel_id="ch",
                        severity=0.0, transmit_latency_ms=transmit, perception_latency_ms=perception)
                status = _REFLEX.verify_reflex(event, signal, operator).status
                expected = _STATUS_TO_VERDICT[status]

                result = run_gates(_packet(risk, irrev, commit, present, transmit, perception, reflex),
                                   PREDICATES, now="T")
                self.assertEqual(
                    result["verdict"], expected,
                    f"status={status} -> expected {expected}, got {result['verdict']}")


if __name__ == "__main__":
    unittest.main()
