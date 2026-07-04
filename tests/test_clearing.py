#!/usr/bin/env python3
"""Clearing cluster probe — does packet->verdict cover multi-party clearing?

Finding: YES for clearing *verification* (conservation / no-conflict / priority),
with zero kernel change. The subject stays single (the clearing round); allocations
are multi-party evidence within one packet. The clearing *computation* is out of
scope (produces the packet, lives in the source project). No ClearingContract needed.
"""

import copy
import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs.loader import load_packs


class TestClearingProbe(unittest.TestCase):
    def setUp(self):
        self.registry = load_packs()
        self.pack = self.registry["packs"]["reserve-flow"]

    def _run(self, pkt):
        return run_gates(pkt, self.pack["predicate_fns"], now="T", schema=self.pack["schema"])

    def test_registered_zero_kernel_change(self):
        self.assertIn("reserve-flow", self.registry["packs"])
        self.assertEqual(self.registry["dropped"], [])

    def test_sample_verdicts(self):
        for sname in ("valid", "thin", "breach"):
            self.assertEqual(self._run(self.pack["samples"][sname])["verdict"], sname)

    def test_conservation_over_allocation_is_breach(self):
        pkt = copy.deepcopy(self.pack["samples"]["valid"])
        pkt["clearing"]["allocations"].append({"party_id": "D", "amount": 999, "priority": 0})
        r = self._run(pkt)
        self.assertEqual(r["verdict"], "breach")

    def test_double_allocation_is_breach(self):
        pkt = copy.deepcopy(self.pack["samples"]["valid"])
        pkt["clearing"]["allocations"].append({"party_id": "A", "amount": 1, "priority": 3})
        r = self._run(pkt)
        self.assertEqual(r["verdict"], "breach")  # party A allocated twice

    def test_subject_is_single_clearing_round(self):
        # multi-party allocations, but the packet's subject is one clearing round
        r = self._run(self.pack["samples"]["valid"])
        self.assertEqual(r["subject"], "RF-VALID-001")

    def test_malformed_clearing_is_schema_breach(self):
        pkt = copy.deepcopy(self.pack["samples"]["valid"])
        del pkt["clearing"]["supply"]  # schema requires supply
        r = self._run(pkt)
        self.assertEqual(r["reason"], "schema_violation")


if __name__ == "__main__":
    unittest.main()
