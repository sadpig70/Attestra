#!/usr/bin/env python3
"""Parity anchor: graph-quarantine pack vs the real GraphQuarantine examples."""

import json
import os
import subprocess
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs import graph_quarantine

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELIX = os.path.dirname(HERE)
SRC = os.path.join(HELIX, "GraphQuarantine", "src")
FIXTURES = [
    ("quarantined-case.json", "breach"),
    ("clear-case.json", "valid"),
    ("invalid-baseline-case.json", "thin"),
]


def _source_receipt(example):
    env = dict(os.environ, PYTHONPATH=SRC)
    path = os.path.join(HELIX, "GraphQuarantine", "examples", example)
    run = subprocess.run([sys.executable, "-m", "graphquarantine", "run", path],
                         cwd=HELIX, env=env, capture_output=True, text=True)
    return json.loads(run.stdout)


def _packet(receipt):
    return {"packet_id": receipt["case_id"], "subject": receipt["case_id"],
            "graph": {"decision": receipt["decision"],
                      "clean_branches": receipt.get("clean_branches", []),
                      "quarantine_set": receipt.get("quarantine_set", []),
                      "blast_radius": receipt.get("blast_radius", 0),
                      "receipt_sha256": receipt["receipt_sha256"],
                      "source_project": "GraphQuarantine"}}


@unittest.skipUnless(os.path.isdir(SRC), "GraphQuarantine source not importable")
class TestGraphQuarantineParity(unittest.TestCase):
    def test_source_fixtures_map_to_attestra_verdicts(self):
        for example, verdict in FIXTURES:
            with self.subTest(example=example):
                result = run_gates(_packet(_source_receipt(example)), graph_quarantine.PREDICATES, now="T")
                self.assertEqual(result["verdict"], verdict)


if __name__ == "__main__":
    unittest.main()

