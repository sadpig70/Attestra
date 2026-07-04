#!/usr/bin/env python3
"""Pack registry + per-pack sample verdict + determinism boundary."""

import os
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_core.determinism import check_tree
from attestra_packs.loader import load_packs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED_PACKS = {
    "handback", "spend-boundary", "veto-escrow", "delegation", "withheld-action",
    "policy-drift", "custody-relay", "slot-gate", "context-boundary", "action-governance",
    "repro-dossier", "gen-cert",  # second wave: provenance/trust cluster
    "reserve-flow",               # clearing cluster probe (verification only)
}


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = load_packs()

    def test_all_packs_loaded(self):
        self.assertEqual(set(self.registry["packs"]), EXPECTED_PACKS)

    def test_no_load_errors(self):
        self.assertEqual(self.registry["errors"], [])

    def test_manifests_have_source_project(self):
        for pack in self.registry["packs"].values():
            self.assertTrue(pack["source_project"].startswith("github.com/sadpig70/"))


class TestPackSampleVerdicts(unittest.TestCase):
    def test_every_pack_sample_matches_its_name(self):
        registry = load_packs()
        for name, pack in registry["packs"].items():
            for sample_name in ("valid", "thin", "breach"):
                pkt = pack["samples"][sample_name]
                result = run_gates(pkt, pack["predicate_fns"], now="T",
                                   id_field=pack.get("id_field", "packet_id"),
                                   schema=pack.get("schema"))
                self.assertEqual(
                    result["verdict"], sample_name,
                    f"pack {name} sample '{sample_name}' -> {result['verdict']} "
                    f"(worst={result.get('worst')})")


class TestDeterminismBoundary(unittest.TestCase):
    def test_core_and_packs_are_deterministic(self):
        report = check_tree(ROOT)
        self.assertTrue(report["clean"], f"determinism violations: {report['violations']}")
        self.assertGreater(report["files_scanned"], 10)


if __name__ == "__main__":
    unittest.main()
