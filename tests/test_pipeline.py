#!/usr/bin/env python3
"""Pipeline composition — SpendBoundary's manual recombination as a first-class feature."""

import unittest

from attestra_packs.loader import load_packs
from attestra_pipeline import run_pipeline

PACKS = ["spend-boundary", "context-boundary", "veto-escrow"]


def _combined(pid, in_veto_window=True, policy_gap=1, spend_ctx="task"):
    return {
        "packet_id": pid, "subject": pid,
        "spend": {"agent_id": "a", "amount": 200, "currency": "USD", "recipient": "acct-ok",
                  "current_context": "task", "spend_context": spend_ctx, "tool_name": "search"},
        "soft_limit": 1000, "blocked_recipients": ["acct-blocked"], "restricted_tools": ["wire"],
        "context": {"crosses_scope": True, "policy_gap": policy_gap, "path_rank": 0.3,
                    "rank_threshold": 0.6},
        "decision": {"in_veto_window": in_veto_window, "escrow_state": "released",
                     "interrupt_latency_ms": 50, "interrupt_bound_ms": 100},
    }


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.registry = load_packs()

    def test_all_valid_composition(self):
        result = run_pipeline(_combined("PIPE-OK"), PACKS, self.registry, now="T")
        self.assertEqual(result["verdict"], "valid")
        self.assertEqual(len(result["pack_results"]), 3)

    def test_one_breach_fails_pipeline(self):
        # veto window closed -> veto-escrow breaches -> whole pipeline breaches
        result = run_pipeline(_combined("PIPE-BAD", in_veto_window=False), PACKS,
                              self.registry, now="T")
        self.assertEqual(result["verdict"], "breach")
        self.assertEqual(result["worst_pack"], "veto-escrow")

    def test_aggregation_is_highest_severity(self):
        # policy_gap=2 -> context-boundary thin, others valid -> pipeline thin
        result = run_pipeline(_combined("PIPE-THIN", policy_gap=2), PACKS,
                              self.registry, now="T")
        self.assertEqual(result["verdict"], "thin")
        self.assertEqual(result["worst_pack"], "context-boundary")


if __name__ == "__main__":
    unittest.main()
