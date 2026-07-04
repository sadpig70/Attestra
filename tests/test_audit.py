#!/usr/bin/env python3
"""Closed audit loop — batch ingest -> route -> verdict -> attest -> ledger -> verify."""

import json
import os
import tempfile
import unittest

from attestra_packs.loader import load_packs
from attestra_audit import run_audit


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.reg = load_packs()

    def _write(self, d, pack, variant, fname=None):
        pkt = self.reg["packs"][pack]["samples"][variant]
        name = fname or f"{pack}.{variant}.json"
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            json.dump(pkt, f, ensure_ascii=False)
        return name

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "handback", "valid")       # valid
            self._write(d, "spend-boundary", "breach")  # breach
            self._write(d, "gen-cert", "thin")         # thin
            self._write(d, "reserve-flow", "valid")    # valid
            with open(os.path.join(d, "mystery.json"), "w", encoding="utf-8") as f:
                json.dump({"packet_id": "X", "foo": 1}, f)  # unroutable

            ledger = os.path.join(d, "audit-ledger.jsonl")
            rep = run_audit(d, self.reg, ledger, now="T", attest_out=os.path.join(d, "att"))

            self.assertEqual(rep["by_verdict"], {"valid": 2, "thin": 1, "breach": 1})
            self.assertEqual(rep["processed"], 4)
            self.assertEqual(len(rep["unroutable"]), 1)
            self.assertTrue(rep["chain"]["valid"])
            self.assertEqual(rep["chain"]["records"], 4)
            # attestations for the 3 non-breach verdicts
            self.assertEqual(rep["attestations_issued"], 3)
            self.assertEqual(len(os.listdir(os.path.join(d, "att"))), 3)

    def test_route_by_pack_field(self):
        with tempfile.TemporaryDirectory() as d:
            pkt = dict(self.reg["packs"]["handback"]["samples"]["valid"])
            pkt["pack"] = "handback"
            with open(os.path.join(d, "anon.json"), "w", encoding="utf-8") as f:
                json.dump(pkt, f)  # filename gives no routable prefix
            rep = run_audit(d, self.reg, os.path.join(d, "l.jsonl"), now="T")
            self.assertEqual(rep["processed"], 1)
            self.assertEqual(rep["unroutable"], [])

    def test_pack_override(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "gen-cert", "valid", fname="whatever.json")
            rep = run_audit(d, self.reg, os.path.join(d, "l.jsonl"), now="T", pack_override="gen-cert")
            self.assertEqual(rep["processed"], 1)
            self.assertEqual(rep["by_pack"], {"gen-cert": 1})

    def test_idempotent_same_now(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "handback", "valid")
            self._write(d, "gen-cert", "valid")
            ledger = os.path.join(d, "l.jsonl")
            run_audit(d, self.reg, ledger, now="T")
            with open(ledger, "r", encoding="utf-8") as f:
                bytes1 = f.read()
            run_audit(d, self.reg, ledger, now="T")  # fresh rebuild, same now
            with open(ledger, "r", encoding="utf-8") as f:
                bytes2 = f.read()
            self.assertEqual(bytes1, bytes2)

    def test_record_hash_time_independent_across_runs(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "handback", "valid")
            ledger = os.path.join(d, "l.jsonl")
            run_audit(d, self.reg, ledger, now="AAA")
            with open(ledger, encoding="utf-8") as f:
                h1 = [json.loads(x)["record_hash"] for x in f]
            run_audit(d, self.reg, ledger, now="ZZZ")
            with open(ledger, encoding="utf-8") as f:
                h2 = [json.loads(x)["record_hash"] for x in f]
            self.assertEqual(h1, h2)  # now is metadata, excluded from record_hash


if __name__ == "__main__":
    unittest.main()
