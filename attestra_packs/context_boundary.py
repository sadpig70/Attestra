#!/usr/bin/env python3
"""ContextBoundaryPack — rank cross-memory-scope context attack paths.

source_project: github.com/sadpig70/ContextCreep
"""

from ._base import valid, thin, breach, section


def scope_crossing(packet, P=None):
    c = section(packet, "context")
    if "crosses_scope" not in c:
        return thin("scope_crossing", "scope crossing not declared")
    return valid("scope_crossing")


def policy_gap(packet, P=None):
    c = section(packet, "context")
    gap = c.get("policy_gap", 0)
    if gap <= 1:
        return valid("policy_gap")
    if gap == 2:
        return thin("policy_gap", "moderate policy gap between scopes")
    return breach("policy_gap", "large policy gap between memory scopes")


def path_rank(packet, P=None):
    c = section(packet, "context")
    rank = c.get("path_rank", 0.0)
    thr = c.get("rank_threshold", 0.6)
    if rank <= thr:
        return valid("path_rank")
    if rank <= thr * 1.25:
        return thin("path_rank", "attack-path rank near threshold")
    return breach("path_rank", "attack-path rank exceeds threshold")


MANIFEST = {
    "name": "context-boundary", "version": "1.0",
    "predicates": ["scope_crossing", "policy_gap", "path_rank"],
    "packet_schema": "schemas/packet-context.schema.json",
    "source_project": "github.com/sadpig70/ContextCreep",
}
PREDICATES = [scope_crossing, policy_gap, path_rank]


def _p(pid, crosses, gap, rank):
    return {"packet_id": pid, "subject": pid,
            "context": {"crosses_scope": crosses, "policy_gap": gap,
                        "path_rank": rank, "rank_threshold": 0.6}}


SAMPLES = {
    "valid": _p("CB-VALID-001", True, 1, 0.3),
    "thin": _p("CB-THIN-001", True, 2, 0.3),
    "breach": _p("CB-BREACH-001", True, 3, 0.9),
}
