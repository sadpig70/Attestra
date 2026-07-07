#!/usr/bin/env python3
"""Parity anchor: attestra_packs.method_bond vs the real MethodBond engine.

MethodBond is an independent repo (github.com/sadpig70/MethodBond); it is not vendored in
Attestra. When its source is importable in a dev checkout, this test asserts the pack's
verdict reproduces engine.evaluate's verdict (certified/conditional/rejected) across
every branch of the three checks. In CI (source absent) it skips.

Point METHODBOND_SRC at the dir holding the MethodBond package, e.g.
    METHODBOND_SRC=D:/HELIX/MethodBond python -m unittest tests.test_method_bond_parity
"""

import os
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.method_bond import PREDICATES


def _load_engine():
    candidates = [os.environ.get("METHODBOND_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "MethodBond"),
        "D:/HELIX/MethodBond",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from MethodBond.engine import evaluate  # noqa: WPS433
        return evaluate
    except Exception:  # noqa: BLE001 — source simply not present here
        return None


_EVAL = _load_engine()

_VERDICT_TO_ATTESTRA = {"certified": "valid", "conditional": "thin", "rejected": "breach"}

_LICENSE_OK = {"transfer_type": "permissive", "source_domain": "open",
               "target_industry": "general", "revenue_share_pct": 10}
_PROV_OK = [
    {"input_hash": "i1", "output_hash": "h1", "build_command": "make", "builder_id": "b1"},
    {"input_hash": "i2", "output_hash": "h1", "build_command": "make", "builder_id": "b2"},
]
_BASE = {"rules": {"max_temp": 100}}


def _art(license_doc=None, provs=None, baseline=None, candidate=None):
    return {"id": "a", "license": _LICENSE_OK if license_doc is None else license_doc,
            "provenances": _PROV_OK if provs is None else provs,
            "baseline_policy": _BASE if baseline is None else baseline,
            "candidate_policy": _BASE if candidate is None else candidate}

# Exercise each branch: certified; license-bad; too-few-provs; mismatched-hashes;
# cert extra-rule drift; cert missing-rule drift; bad transfer_type.
_CASES = [
    _art(),
    _art(license_doc={}),
    _art(provs=[_PROV_OK[0]]),
    _art(provs=[{**_PROV_OK[0], "output_hash": "h1"}, {**_PROV_OK[1], "output_hash": "h2"}]),
    _art(candidate={"rules": {"max_temp": 100, "extra": 1}}),
    _art(candidate={"rules": {}}),
    _art(license_doc={**_LICENSE_OK, "transfer_type": "bogus"}),
]


def _packet(art):
    return {"packet_id": "P", "subject": "P", "license": art["license"],
            "provenances": art["provenances"], "baseline_policy": art["baseline_policy"],
            "candidate_policy": art["candidate_policy"]}


@unittest.skipUnless(_EVAL is not None, "MethodBond source not importable (independent repo)")
class TestMethodBondParity(unittest.TestCase):
    def test_verdict_matches_source(self):
        for i, art in enumerate(_CASES):
            with self.subTest(case=i):
                src = _EVAL(art)["verdict"]
                expected = _VERDICT_TO_ATTESTRA[src]
                result = run_gates(_packet(art), PREDICATES, now="T")
                self.assertEqual(
                    result["verdict"], expected,
                    f"source={src} -> expected {expected}, got {result['verdict']} (worst={result.get('worst')})")


if __name__ == "__main__":
    unittest.main()
