#!/usr/bin/env python3
"""Second-wave packs — provenance/trust cluster generalization probe.

These packs belong to a DIFFERENT corpus sub-cluster than the ten first-wave
agent-action governance packs. They were added with zero kernel change (manifest
+ predicates + schema only). This test documents that the PackContract generalizes
across clusters.
"""

import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.loader import load_packs

SECOND_WAVE = {"repro-dossier", "gen-cert"}


class TestSecondWaveGeneralization(unittest.TestCase):
    def setUp(self):
        self.registry = load_packs()

    def test_second_wave_packs_registered(self):
        self.assertTrue(SECOND_WAVE <= set(self.registry["packs"]))
        for name in SECOND_WAVE:
            self.assertEqual(self.registry["packs"][name]["fingerprint"] and True, True)

    def test_distinct_cluster_source_projects(self):
        for name in SECOND_WAVE:
            src = self.registry["packs"][name]["source_project"]
            self.assertIn(src, ("github.com/sadpig70/ReproDossier", "github.com/sadpig70/GenCert"))

    def test_sample_verdicts(self):
        for name in SECOND_WAVE:
            pack = self.registry["packs"][name]
            for sname in ("valid", "thin", "breach"):
                result = run_gates(pack["samples"][sname], pack["predicate_fns"], now="T",
                                   schema=pack.get("schema"))
                self.assertEqual(result["verdict"], sname,
                                 f"{name}.{sname} -> {result['verdict']} (worst={result.get('worst')})")

    def test_no_dedup_collision_with_first_wave(self):
        # second-wave fingerprints must be distinct from all first-wave packs
        self.assertEqual(self.registry["dropped"], [])
        fps = [p["fingerprint"] for p in self.registry["packs"].values()]
        self.assertEqual(len(fps), len(set(fps)))


if __name__ == "__main__":
    unittest.main()
