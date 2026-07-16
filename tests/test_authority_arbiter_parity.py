#!/usr/bin/env python3
"""Parity anchor: authority-arbiter pack vs the real AuthorityArbiter examples."""

import json
import os
import subprocess
import sys
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs import authority_arbiter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELIX = os.path.dirname(HERE)
SRC = os.path.join(HELIX, "AuthorityArbiter", "src")
FIXTURES = [
    ("allow-request.json", "valid"),
    ("deny-request.json", "breach"),
    ("tie-escalation-request.json", "thin"),
]


def _source_receipt(example):
    env = dict(os.environ, PYTHONPATH=SRC)
    path = os.path.join(HELIX, "AuthorityArbiter", "examples", example)
    run = subprocess.run([sys.executable, "-m", "authorityarbiter", "run", path],
                         cwd=HELIX, env=env, capture_output=True, text=True)
    return json.loads(run.stdout)


def _packet(receipt):
    handback = receipt.get("handback", {})
    return {"packet_id": receipt["case_id"], "subject": receipt["case_id"],
            "arbiter": {"decision": receipt["decision"],
                        "selected_authority": receipt.get("selected_authority", ""),
                        "receipt_sha256": receipt["receipt_sha256"],
                        "source_project": "AuthorityArbiter"},
            "handback": {"route_id": handback.get("route_id", ""),
                         "return_to": handback.get("return_to", ""),
                         "confirmed": handback.get("confirmed", False)}}


@unittest.skipUnless(os.path.isdir(SRC), "AuthorityArbiter source not importable")
class TestAuthorityArbiterParity(unittest.TestCase):
    def test_source_fixtures_map_to_attestra_verdicts(self):
        for example, verdict in FIXTURES:
            with self.subTest(example=example):
                result = run_gates(_packet(_source_receipt(example)), authority_arbiter.PREDICATES, now="T")
                self.assertEqual(result["verdict"], verdict)


if __name__ == "__main__":
    unittest.main()

