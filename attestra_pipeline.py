#!/usr/bin/env python3
"""Pipeline — apply several packs to one packet and aggregate their verdicts.

Generalizes SpendBoundary's hand-wired (ContextCreep+SpendMesh+VetoEscrow)
recombination into a first-class composition: any packet can be run through a
list of packs, and the pipeline verdict is the highest severity across packs.
Deterministic — order-independent aggregation, no clock/network/AI.
"""

from attestra_core.gate_runtime import run_gates
from attestra_core.verdict import aggregate_verdict
from attestra_packs.loader import get_pack


def run_pipeline(packet, pack_names, registry, P=None, now=""):
    """Compose: run each pack over the packet. Aggregate: highest severity wins."""
    P = P or {}
    pack_results = []
    for name in pack_names:
        pack = get_pack(registry, name)
        r = run_gates(packet, pack["predicate_fns"], P, now=now,
                      id_field=pack.get("id_field", "packet_id"),
                      schema=pack.get("schema"))
        pack_results.append({"pack": name, **r})
    agg = aggregate_verdict(
        [{"gate": pr["pack"], "verdict": pr["verdict"], "reason": pr["reason"]}
         for pr in pack_results]
    )
    return {
        "subject": pack_results[0]["subject"] if pack_results else "",
        "verdict": agg["verdict"], "worst_pack": agg["worst"],
        "pack_results": pack_results, "evaluated_at": now,
    }
