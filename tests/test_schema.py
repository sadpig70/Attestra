#!/usr/bin/env python3
"""Packet-schema enforcement — the structural contract runs before predicates."""

import copy
import unittest

from attestra_core.schema import validate_against_schema
from attestra_core.gate_runtime import run_gates
from attestra_packs.loader import load_packs


class TestMiniValidator(unittest.TestCase):
    def test_type_and_required(self):
        schema = {"type": "object", "required": ["a"],
                  "properties": {"a": {"type": "integer"}}}
        self.assertTrue(validate_against_schema({"a": 3}, schema)["ok"])
        self.assertFalse(validate_against_schema({"a": "x"}, schema)["ok"])  # wrong type
        self.assertFalse(validate_against_schema({}, schema)["ok"])          # missing required

    def test_bool_is_not_integer(self):
        schema = {"type": "integer"}
        self.assertFalse(validate_against_schema(True, schema)["ok"])

    def test_nested_and_array(self):
        schema = {"type": "object", "properties": {
            "s": {"type": "object", "properties": {"n": {"type": "number"}}},
            "xs": {"type": "array", "items": {"type": "string"}}}}
        self.assertTrue(validate_against_schema({"s": {"n": 1.5}, "xs": ["a"]}, schema)["ok"])
        self.assertFalse(validate_against_schema({"s": {"n": "no"}}, schema)["ok"])
        self.assertFalse(validate_against_schema({"xs": [1]}, schema)["ok"])


class TestSchemaLoadedForEveryPack(unittest.TestCase):
    def setUp(self):
        self.registry = load_packs()

    def test_all_packs_have_a_schema(self):
        self.assertEqual(self.registry["errors"], [])
        for name, pack in self.registry["packs"].items():
            self.assertIsInstance(pack["schema"], dict, f"{name} has no loaded schema")

    def test_samples_conform_to_schema(self):
        for name, pack in self.registry["packs"].items():
            for sname, pkt in pack["samples"].items():
                sv = validate_against_schema(pkt, pack["schema"])
                self.assertTrue(sv["ok"], f"{name}.{sname} violates its schema: {sv['errors']}")


class TestEnforcementInGateRuntime(unittest.TestCase):
    def setUp(self):
        self.registry = load_packs()

    def test_missing_section_is_schema_breach(self):
        pack = self.registry["packs"]["veto-escrow"]
        pkt = copy.deepcopy(pack["samples"]["valid"])
        del pkt["decision"]  # structurally malformed
        result = run_gates(pkt, pack["predicate_fns"], now="T", schema=pack["schema"])
        self.assertEqual(result["verdict"], "breach")
        self.assertEqual(result["reason"], "schema_violation")

    def test_wrong_type_is_schema_breach(self):
        pack = self.registry["packs"]["spend-boundary"]
        pkt = copy.deepcopy(pack["samples"]["valid"])
        pkt["spend"]["amount"] = "a lot"  # wrong type
        result = run_gates(pkt, pack["predicate_fns"], now="T", schema=pack["schema"])
        self.assertEqual(result["verdict"], "breach")
        self.assertEqual(result["worst"], "schema")

    def test_schema_checked_before_predicates(self):
        pack = self.registry["packs"]["action-governance"]
        pkt = copy.deepcopy(pack["samples"]["breach"])  # would breach on predicate too
        del pkt["action"]
        result = run_gates(pkt, pack["predicate_fns"], now="T", schema=pack["schema"])
        self.assertEqual(result["reason"], "schema_violation")  # schema wins, predicates skipped
        self.assertEqual(result["checks"], [])


if __name__ == "__main__":
    unittest.main()
