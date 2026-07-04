#!/usr/bin/env python3
"""Docs gate — the three docs exist and describe the ACTUAL contract (no drift)."""

import os
import unittest

from attestra_packs.loader import _REQUIRED_MANIFEST
from attestra_core.packet import PRIVATE_FIELDS
from attestra_packs import _base, action_governance

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")


def _read(name):
    with open(os.path.join(DOCS, name), "r", encoding="utf-8") as f:
        return f.read()


class TestDocsPresent(unittest.TestCase):
    def test_three_docs_substantial(self):
        for name in ("ARCHITECTURE.md", "PACK-CONTRACT.md", "DETERMINISM.md"):
            self.assertTrue(os.path.exists(os.path.join(DOCS, name)), f"missing {name}")
            self.assertGreater(len(_read(name)), 800, f"{name} too thin")


class TestPackContractMatchesCode(unittest.TestCase):
    def setUp(self):
        self.txt = _read("PACK-CONTRACT.md")

    def test_manifest_required_keys_documented(self):
        for key in _REQUIRED_MANIFEST:
            self.assertIn(key, self.txt, f"PACK-CONTRACT omits manifest key '{key}'")

    def test_checkresult_keys_documented(self):
        for key in _base.valid("g"):  # actual CheckResult keys
            self.assertIn(key, self.txt, f"PACK-CONTRACT omits CheckResult key '{key}'")

    def test_private_fields_documented(self):
        for field in PRIVATE_FIELDS:
            self.assertIn(field, self.txt, f"PACK-CONTRACT omits private field '{field}'")

    def test_documented_module_shape_matches_a_real_pack(self):
        # a real pack must satisfy exactly what the doc tells authors to provide
        self.assertIsInstance(action_governance.MANIFEST, dict)
        self.assertTrue(all(k in action_governance.MANIFEST for k in _REQUIRED_MANIFEST))
        self.assertTrue(action_governance.PREDICATES and
                        all(callable(p) for p in action_governance.PREDICATES))
        self.assertTrue({"valid", "thin", "breach"} <= set(action_governance.SAMPLES))


class TestDeterminismDocMatchesChecker(unittest.TestCase):
    def test_forbidden_terms_documented(self):
        txt = _read("DETERMINISM.md")
        for term in ("random", "socket", "datetime.now", "record_hash"):
            self.assertIn(term, txt)


if __name__ == "__main__":
    unittest.main()
