#!/usr/bin/env python3
"""Parity anchor: proof-escrow pack vs the real ProofEscrow source examples."""

import json
import os
import subprocess
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs import proof_escrow

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELIX = os.path.dirname(HERE)
SRC = os.path.join(HELIX, "ProofEscrow", "src")
TRUST = os.path.join(HELIX, "ProofEscrow", "examples", "trust-store.json")
FIXTURES = [
    ("released-request.json", "valid"),
    ("held-signature-request.json", "breach"),
    ("held-behavior-request.json", "breach"),
]


def _source_receipt(example):
    env = dict(os.environ, PYTHONPATH=SRC)
    path = os.path.join(HELIX, "ProofEscrow", "examples", example)
    run = subprocess.run(
        [sys.executable, "-m", "proofescrow", "run", "--trust-store", TRUST, path],
        cwd=HELIX, env=env, capture_output=True, text=True
    )
    return json.loads(run.stdout)


def _packet(receipt):
    return {"packet_id": receipt["escrow_id"], "subject": receipt["escrow_id"],
            "escrow": {"decision": receipt["decision"],
                       "reasons": receipt.get("reasons", []),
                       "receipt_sha256": receipt["receipt_sha256"],
                       "source_project": "ProofEscrow"}}


@unittest.skipUnless(os.path.isdir(SRC), "ProofEscrow source not importable")
class TestProofEscrowParity(unittest.TestCase):
    def test_source_fixtures_map_to_attestra_verdicts(self):
        for example, verdict in FIXTURES:
            with self.subTest(example=example):
                result = run_gates(_packet(_source_receipt(example)), proof_escrow.PREDICATES, now="T")
                self.assertEqual(result["verdict"], verdict)


if __name__ == "__main__":
    unittest.main()

