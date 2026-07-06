#!/usr/bin/env python3
"""Parity anchor: attestra_packs.pqc_mesh vs the real PqcMesh reference.

PqcMesh is an independent repo (github.com/sadpig70/PqcMesh); it is not vendored
in Attestra. When its source is importable in a dev checkout, this test asserts
the pack's inline reference table reproduces PqcMesh's published algorithm
verdicts exactly. In CI (source absent) it skips — the pack stays self-contained.

Point PQCMESH_SRC at the project's ``src`` dir to run it, e.g.
    PQCMESH_SRC=D:/IdeaFirst/pqcmesh/src python -m unittest tests.test_pqc_mesh_parity
"""

import os
import sys
import unittest

from attestra_packs.pqc_mesh import quantum_verdict as pack_qv


def _load_pqcmesh():
    candidates = [os.environ.get("PQCMESH_SRC")]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(here, "..", "pqcmesh", "src"),
        os.path.join(here, "..", "PqcMesh", "src"),
        "D:/IdeaFirst/pqcmesh/src",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        from pqcmesh.models import ALGORITHM_TABLE  # noqa: WPS433
        return ALGORITHM_TABLE
    except Exception:  # noqa: BLE001 — source simply not present here
        return None


_TABLE = _load_pqcmesh()


@unittest.skipUnless(_TABLE is not None, "PqcMesh source not importable (independent repo)")
class TestPqcMeshParity(unittest.TestCase):
    def test_algorithm_table_matches_source(self):
        mismatches = []
        for alg, prof in _TABLE.items():
            if pack_qv(alg) != (prof.verdict, prof.severity):
                mismatches.append((alg, pack_qv(alg), (prof.verdict, prof.severity)))
        self.assertEqual(mismatches, [], f"pack table diverges from PqcMesh: {mismatches}")

    def test_unknown_algorithm_is_conservatively_broken(self):
        # PqcMesh assumes the worst for an unrecognized algorithm; the pack must too.
        self.assertEqual(pack_qv("no_such_algorithm_v9"), ("quantum_broken", 3))


if __name__ == "__main__":
    unittest.main()
