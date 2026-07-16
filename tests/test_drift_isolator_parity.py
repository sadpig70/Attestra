#!/usr/bin/env python3
"""Parity anchor: drift-isolator pack vs the real DriftIsolator examples."""

import json
import os
import subprocess
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs import drift_isolator

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELIX = os.path.dirname(HERE)
SRC = os.path.join(HELIX, "DriftIsolator", "src")
FIXTURES = [
    ("drift-case.json", "breach"),
    ("no-drift-case.json", "valid"),
    ("invalid-baseline-case.json", "thin"),
]


def _source_receipt(example):
    env = dict(os.environ, PYTHONPATH=SRC)
    path = os.path.join(HELIX, "DriftIsolator", "examples", example)
    run = subprocess.run([sys.executable, "-m", "driftisolator", "run", path],
                         cwd=HELIX, env=env, capture_output=True, text=True)
    return json.loads(run.stdout)


def _packet(receipt):
    return {"packet_id": receipt["case_id"], "subject": receipt["case_id"],
            "drift": {"decision": receipt["decision"],
                      "minimal_event_count": receipt.get("minimal_event_count", 0),
                      "one_minimal": receipt.get("one_minimal", False),
                      "original_event_count": receipt.get("original_event_count", 0),
                      "receipt_sha256": receipt["receipt_sha256"],
                      "source_project": "DriftIsolator"}}


@unittest.skipUnless(os.path.isdir(SRC), "DriftIsolator source not importable")
class TestDriftIsolatorParity(unittest.TestCase):
    def test_source_fixtures_map_to_attestra_verdicts(self):
        for example, verdict in FIXTURES:
            with self.subTest(example=example):
                result = run_gates(_packet(_source_receipt(example)), drift_isolator.PREDICATES, now="T")
                self.assertEqual(result["verdict"], verdict)


if __name__ == "__main__":
    unittest.main()

