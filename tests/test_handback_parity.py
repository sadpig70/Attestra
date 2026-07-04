#!/usr/bin/env python3
"""Reference-pack parity — HandbackPack must reproduce ActionHandbackVerifier verdicts.

The correctness anchor for the whole platform: the three canonical sample packets
(valid/thin/breach) must aggregate to their namesake verdict through the kernel.
"""

import unittest

from attestra_core.gate_runtime import run_gates
from attestra_packs import handback


class TestHandbackParity(unittest.TestCase):
    def _run(self, name):
        pkt = handback.SAMPLES[name]
        return run_gates(pkt, handback.PREDICATES, now="T", id_field="handback_id")

    def test_valid_sample(self):
        self.assertEqual(self._run("valid")["verdict"], "valid")

    def test_thin_sample(self):
        self.assertEqual(self._run("thin")["verdict"], "thin")

    def test_breach_sample(self):
        self.assertEqual(self._run("breach")["verdict"], "breach")

    def test_five_predicates(self):
        self.assertEqual(len(handback.PREDICATES), 5)
        self.assertEqual(handback.MANIFEST["predicates"],
                         ["authority", "custody", "route", "rollback", "trace"])

    def test_trace_binds_public_surface(self):
        # tampering with the packet after binding must break the trace digest
        import copy
        pkt = copy.deepcopy(handback.SAMPLES["valid"])
        pkt["delegation"]["authority_id"] = "AUTH-TAMPERED"
        result = run_gates(pkt, handback.PREDICATES, now="T", id_field="handback_id")
        self.assertEqual(result["verdict"], "breach")


if __name__ == "__main__":
    unittest.main()
