#!/usr/bin/env python3
"""HELIX bridge — attest a HELIX root read-only; issued attestations independently verify."""

import copy
import json
import os
import tempfile
import unittest

from attestra_core.attestation import verify_attestation
from attestra_packs.loader import load_packs
from attestra_packs import handback
from attestra_helix import helix_audit, is_handback_packet, registry_inventory


def _make_helix_root(root):
    es = os.path.join(root, "examples", "exploit_state")
    os.makedirs(es)
    # a real-shaped HELIX handback packet (identical to Attestra handback format)
    with open(os.path.join(es, "handback_packet.json"), "w", encoding="utf-8") as f:
        json.dump(handback.SAMPLES["valid"], f, ensure_ascii=False, sort_keys=True)
    # non-handback siblings that must be skipped benignly
    with open(os.path.join(es, "candidates.json"), "w", encoding="utf-8") as f:
        json.dump({"candidates": []}, f)
    reg = {"schema_version": "1", "generated_projects": {
        "WithheldActionWitness": {"status": "done", "semantic_family": "handback-family",
                                  "archetype": "verifier", "verdict_scheme": "valid|thin|breach",
                                  "repo_url": "github.com/sadpig70/WithheldActionWitness"}}}
    os.makedirs(os.path.join(root, ".recreate"))
    with open(os.path.join(root, ".recreate", "registry.json"), "w", encoding="utf-8") as f:
        json.dump(reg, f)


class TestHelixBridge(unittest.TestCase):
    def setUp(self):
        self.packs = load_packs()

    def test_helix_handback_shape_matches_attestra(self):
        self.assertTrue(is_handback_packet(handback.SAMPLES["valid"]))

    def test_attest_helix_root(self):
        with tempfile.TemporaryDirectory() as hr, tempfile.TemporaryDirectory() as out:
            _make_helix_root(hr)
            ledger = os.path.join(out, "helix-ledger.jsonl")  # Attestra-side, outside helix_root
            att_ledger = os.path.join(out, "att.jsonl")
            rep = helix_audit(hr, self.packs, ledger, now="T",
                              att_ledger=att_ledger, attest_out=os.path.join(out, "att"))
            self.assertEqual(rep["handback_packets"], 1)
            self.assertEqual(rep["by_verdict"]["valid"], 1)
            self.assertTrue(rep["chain"]["valid"])
            self.assertTrue(rep["att_chain"]["valid"])
            self.assertEqual(rep["attestations_issued"], 1)
            # non-handback file skipped benignly
            self.assertTrue(any(s["file"] == "candidates.json" for s in rep["skipped"]))
            # registry inventory surfaced
            self.assertEqual(len(rep["inventory"]), 1)
            self.assertEqual(rep["inventory"][0]["project"], "WithheldActionWitness")

    def test_read_only_helix_root(self):
        with tempfile.TemporaryDirectory() as hr, tempfile.TemporaryDirectory() as out:
            _make_helix_root(hr)
            es = os.path.join(hr, "examples", "exploit_state")
            before = {p: os.path.getmtime(os.path.join(es, p)) for p in os.listdir(es)}
            helix_audit(hr, self.packs, os.path.join(out, "l.jsonl"), now="T",
                        att_ledger=os.path.join(out, "a.jsonl"))
            after = {p: os.path.getmtime(os.path.join(es, p)) for p in os.listdir(es)}
            self.assertEqual(before, after)  # no files added/modified under helix_root

    def test_issued_attestation_independently_verifies(self):
        with tempfile.TemporaryDirectory() as hr, tempfile.TemporaryDirectory() as out:
            _make_helix_root(hr)
            adir = os.path.join(out, "att")
            helix_audit(hr, self.packs, os.path.join(out, "l.jsonl"), now="T", attest_out=adir)
            files = os.listdir(adir)
            self.assertEqual(len(files), 1)
            with open(os.path.join(adir, files[0]), "r", encoding="utf-8") as f:
                att = json.load(f)
            self.assertTrue(verify_attestation(att)["valid"])

    def test_breach_helix_packet(self):
        with tempfile.TemporaryDirectory() as hr, tempfile.TemporaryDirectory() as out:
            _make_helix_root(hr)
            es = os.path.join(hr, "examples", "exploit_state")
            bad = copy.deepcopy(handback.SAMPLES["breach"])
            with open(os.path.join(es, "handback_packet.json"), "w", encoding="utf-8") as f:
                json.dump(bad, f, ensure_ascii=False, sort_keys=True)
            rep = helix_audit(hr, self.packs, os.path.join(out, "l.jsonl"), now="T")
            self.assertEqual(rep["by_verdict"]["breach"], 1)
            self.assertEqual(rep["attestations_issued"], 0)  # breach -> no attestation


if __name__ == "__main__":
    unittest.main()
