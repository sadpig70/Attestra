#!/usr/bin/env python3
"""Parity anchor: hook-circuit pack vs the real HookCircuit examples."""

import json
import os
import subprocess
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs import hook_circuit

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELIX = os.path.dirname(HERE)
SRC = os.path.join(HELIX, "HookCircuit", "src")
FIXTURES = [
    ("tripped-case.json", "breach"),
    ("clean-case.json", "valid"),
    ("invalid-baseline-case.json", "thin"),
]


def _source_receipt(example):
    env = dict(os.environ, PYTHONPATH=SRC)
    path = os.path.join(HELIX, "HookCircuit", "examples", example)
    run = subprocess.run([sys.executable, "-m", "hookcircuit", "run", path],
                         cwd=HELIX, env=env, capture_output=True, text=True)
    return json.loads(run.stdout)


def _packet(receipt):
    return {"packet_id": receipt["case_id"], "subject": receipt["case_id"],
            "hook": {"decision": receipt["decision"],
                     "tripped_hooks": receipt.get("tripped_hooks", []),
                     "allowed_hooks": receipt.get("allowed_hooks", []),
                     "interrupted": receipt.get("interrupted", False),
                     "receipt_sha256": receipt["receipt_sha256"],
                     "source_project": "HookCircuit"}}


@unittest.skipUnless(os.path.isdir(SRC), "HookCircuit source not importable")
class TestHookCircuitParity(unittest.TestCase):
    def test_source_fixtures_map_to_attestra_verdicts(self):
        for example, verdict in FIXTURES:
            with self.subTest(example=example):
                result = run_gates(_packet(_source_receipt(example)), hook_circuit.PREDICATES, now="T")
                self.assertEqual(result["verdict"], verdict)


if __name__ == "__main__":
    unittest.main()

