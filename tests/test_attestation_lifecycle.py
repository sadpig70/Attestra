#!/usr/bin/env python3
"""Attestation lifecycle — issue -> verify -> revoke, with a hash-chained event ledger."""

import copy
import os
import tempfile
import unittest

from attestra_core.verdict import valid, thin
from attestra_core.attestation import issue_attestation, verify_attestation, recompute_attestation_id
from attestra_core.attestation_ledger import (
    record_issue, record_revoke, revoked_ids, verify_attestation_ledger, list_events,
)

VALID_RESULT = {"verdict": "valid", "subject": "S1", "pack": "handback",
                "checks": [valid("authority"), valid("custody")]}


class TestVerify(unittest.TestCase):
    def test_fresh_attestation_verifies(self):
        att = issue_attestation(VALID_RESULT, now="T")
        r = verify_attestation(att)
        self.assertTrue(r["valid"])
        self.assertTrue(r["id_ok"])
        self.assertFalse(r["revoked"])

    def test_tamper_breaks_binding(self):
        att = issue_attestation(VALID_RESULT, now="T")
        tampered = copy.deepcopy(att)
        tampered["subject"] = "S1-EVIL"
        r = verify_attestation(tampered)
        self.assertFalse(r["valid"])
        self.assertFalse(r["id_ok"])

    def test_issued_at_does_not_affect_id(self):
        a1 = issue_attestation(VALID_RESULT, now="AAA")
        a2 = issue_attestation(VALID_RESULT, now="ZZZ")
        self.assertEqual(a1["attestation_id"], a2["attestation_id"])
        self.assertEqual(recompute_attestation_id(a1), a1["attestation_id"])

    def test_revoked_attestation_is_invalid(self):
        att = issue_attestation(VALID_RESULT, now="T")
        r = verify_attestation(att, revoked={att["attestation_id"]})
        self.assertFalse(r["valid"])
        self.assertTrue(r["revoked"])
        self.assertTrue(r["id_ok"])  # body still binds; it's just revoked


class TestAttestationLedger(unittest.TestCase):
    def test_issue_then_revoke_flow(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "att-ledger.jsonl")
            att = issue_attestation(VALID_RESULT, now="T")
            record_issue(ledger, att, now="T1")
            self.assertEqual(revoked_ids(ledger), set())
            self.assertTrue(verify_attestation(att, revoked_ids(ledger))["valid"])

            record_revoke(ledger, att["attestation_id"], reason="key compromise", now="T2")
            self.assertIn(att["attestation_id"], revoked_ids(ledger))
            self.assertFalse(verify_attestation(att, revoked_ids(ledger))["valid"])
            self.assertEqual(len(list_events(ledger)), 2)

    def test_chain_verifies_and_detects_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "att-ledger.jsonl")
            a = issue_attestation(VALID_RESULT, now="T")
            record_issue(ledger, a, now="T1")
            record_revoke(ledger, a["attestation_id"], reason="x", now="T2")
            self.assertTrue(verify_attestation_ledger(ledger)["valid"])
            with open(ledger, "r", encoding="utf-8") as f:
                lines = f.readlines()
            lines[0] = lines[0].replace('"issue"', '"revoke"')
            with open(ledger, "w", encoding="utf-8") as f:
                f.writelines(lines)
            self.assertFalse(verify_attestation_ledger(ledger)["valid"])

    def test_record_hash_time_independent(self):
        with tempfile.TemporaryDirectory() as d:
            l1 = os.path.join(d, "a.jsonl")
            l2 = os.path.join(d, "b.jsonl")
            att = issue_attestation(VALID_RESULT, now="T")
            r1 = record_issue(l1, att, now="AAA")
            r2 = record_issue(l2, att, now="ZZZ")
            self.assertEqual(r1["record_hash"], r2["record_hash"])


class TestThinAlsoIssuable(unittest.TestCase):
    def test_thin_conditional_attestation_verifies(self):
        att = issue_attestation({"verdict": "thin", "subject": "S2", "pack": "gen-cert",
                                 "checks": [thin("cert_scope", "unspecified")]}, now="T")
        self.assertEqual(att["grade"], "conditional")
        self.assertTrue(verify_attestation(att)["valid"])


if __name__ == "__main__":
    unittest.main()
