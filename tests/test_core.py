#!/usr/bin/env python3
"""Kernel tests — verdict algebra, packet validation, ledger chain, fingerprint, attestation."""

import os
import tempfile
import unittest

from attestra_core.verdict import valid, thin, breach, aggregate_verdict, SEVERITY
from attestra_core.packet import validate_packet, has_private_payload, find_private_fields
from attestra_core.ledger import append_record, verify_ledger, canonical_json, build_record
from attestra_core.fingerprint import fingerprint_pack, fingerprint
from attestra_core.attestation import issue_attestation
from attestra_core.gate_runtime import run_gates


class TestVerdictAlgebra(unittest.TestCase):
    def test_severity_order(self):
        self.assertLess(SEVERITY["valid"], SEVERITY["thin"])
        self.assertLess(SEVERITY["thin"], SEVERITY["breach"])

    def test_aggregate_highest_severity(self):
        checks = [valid("a"), thin("b", "x"), breach("c", "y")]
        self.assertEqual(aggregate_verdict(checks)["verdict"], "breach")
        self.assertEqual(aggregate_verdict(checks)["worst"], "c")

    def test_aggregate_order_independent(self):
        a = aggregate_verdict([valid("a"), thin("b", "x")])
        b = aggregate_verdict([thin("b", "x"), valid("a")])
        self.assertEqual(a["verdict"], b["verdict"])

    def test_empty_checks_is_thin(self):
        self.assertEqual(aggregate_verdict([])["verdict"], "thin")


class TestPacket(unittest.TestCase):
    def test_private_payload_rejected(self):
        pkt = {"packet_id": "P1", "secret": "x"}
        pv = validate_packet(pkt)
        self.assertFalse(pv["ok"])
        self.assertEqual(pv["reason"], "private_payload_present")

    def test_nested_private_payload_detected(self):
        pkt = {"packet_id": "P1", "a": {"b": {"credential": "x"}}}
        self.assertTrue(has_private_payload(pkt))
        self.assertIn("a.b.credential", find_private_fields(pkt))

    def test_missing_identifier(self):
        self.assertFalse(validate_packet({"foo": 1})["ok"])

    def test_valid_packet(self):
        self.assertTrue(validate_packet({"packet_id": "P1"})["ok"])


class TestLedger(unittest.TestCase):
    def _result(self, subj, verdict):
        return {"subject": subj, "verdict": verdict, "checks": [], "evaluated_at": "T"}

    def test_chain_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.jsonl")
            append_record(path, self._result("S1", "valid"), "handback", now="T1")
            append_record(path, self._result("S2", "thin"), "handback", now="T2")
            report = verify_ledger(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["records"], 2)

    def test_hash_time_independent(self):
        r1 = build_record("", self._result("S1", "valid"), "handback", now="AAA")
        r2 = build_record("", self._result("S1", "valid"), "handback", now="ZZZ")
        self.assertEqual(r1["record_hash"], r2["record_hash"])  # now excluded from hash

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.jsonl")
            append_record(path, self._result("S1", "valid"), "handback", now="T1")
            append_record(path, self._result("S2", "valid"), "handback", now="T2")
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            lines[0] = lines[0].replace('"valid"', '"breach"')
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            self.assertFalse(verify_ledger(path)["valid"])


class TestFingerprintDedup(unittest.TestCase):
    def test_same_surface_same_fingerprint(self):
        a = {"name": "x", "predicates": ["p1", "p2"], "packet_schema": "s"}
        b = {"name": "y", "predicates": ["p2", "p1"], "packet_schema": "s"}  # renamed, reordered
        self.assertEqual(fingerprint_pack(a), fingerprint_pack(b))

    def test_different_surface_different_fingerprint(self):
        a = {"name": "x", "predicates": ["p1"], "packet_schema": "s"}
        b = {"name": "x", "predicates": ["p1", "p2"], "packet_schema": "s"}
        self.assertNotEqual(fingerprint_pack(a), fingerprint_pack(b))

    def test_fingerprint_deterministic(self):
        self.assertEqual(fingerprint("a", "b"), fingerprint("b", "a"))


class TestAttestation(unittest.TestCase):
    def test_breach_refused(self):
        self.assertIsNone(issue_attestation({"verdict": "breach", "checks": [], "subject": "S"}))

    def test_valid_full_grade(self):
        att = issue_attestation({"verdict": "valid", "checks": [valid("a")], "subject": "S"}, now="T")
        self.assertEqual(att["grade"], "full")
        self.assertTrue(att["attestation_id"].startswith("ATT-"))

    def test_thin_conditional_grade(self):
        att = issue_attestation({"verdict": "thin", "checks": [thin("a", "x")], "subject": "S"})
        self.assertEqual(att["grade"], "conditional")

    def test_attestation_id_idempotent(self):
        r = {"verdict": "valid", "checks": [valid("a")], "subject": "S"}
        self.assertEqual(issue_attestation(r, now="A")["attestation_id"],
                         issue_attestation(r, now="B")["attestation_id"])

    def test_multi_check_digest_order_independent(self):
        # digest_checks must handle many checks and be order-independent
        r1 = {"verdict": "thin", "subject": "S",
              "checks": [valid("a"), thin("b", "x"), valid("c")]}
        r2 = {"verdict": "thin", "subject": "S",
              "checks": [valid("c"), valid("a"), thin("b", "x")]}
        self.assertEqual(issue_attestation(r1)["checks_digest"],
                         issue_attestation(r2)["checks_digest"])


class TestGateRuntimePacketReject(unittest.TestCase):
    def test_private_payload_breach_no_predicates(self):
        called = []

        def pred(pkt, P):
            called.append(1)
            return valid("g")

        result = run_gates({"packet_id": "P", "secret": "x"}, [pred])
        self.assertEqual(result["verdict"], "breach")
        self.assertFalse(result["packet_ok"])
        self.assertEqual(called, [])  # predicates never ran


if __name__ == "__main__":
    unittest.main()
