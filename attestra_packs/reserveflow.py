#!/usr/bin/env python3
"""ReserveFlow (clearing cluster probe) — VERIFY a strategic-reserve flow clearing.

source_project: github.com/sadpig70/ReserveFlow
Cluster: clearing/market — structurally the MOST distant from governance/provenance
(multi-party allocation, not single-subject evidence). This pack is a boundary probe.

FINDING (see .pgf DESIGN §4 / status clearing_probe_finding):
  Attestra's packet->predicate->verdict contract COVERS clearing *verification*
  (does a cleared allocation satisfy conservation / no-conflict / priority?) with
  ZERO kernel change. The subject is the clearing ROUND (still single-subject); the
  multi-party allocations are evidence inside one packet. The clearing *computation*
  (the matching/allocation engine) is NOT in scope — it produces the packet and lives
  in the source project, exactly like the already-declared out-of-boundary domain
  stage. => No ClearingContract extension is needed at the verdict layer.
"""

from ._base import valid, thin, breach, section


def _prio_of(requests, party_id):
    for r in requests:
        if r.get("party_id") == party_id:
            return r.get("priority", 0)
    return 0


def conservation(packet, P=None):
    c = section(packet, "clearing")
    supply = c.get("supply")
    if supply is None:
        return breach("conservation", "no declared supply")
    total = sum(a.get("amount", 0) for a in c.get("allocations", []))
    if total <= supply:
        return valid("conservation")
    return breach("conservation", f"allocated {total} exceeds supply {supply}")


def no_conflict(packet, P=None):
    allocs = section(packet, "clearing").get("allocations", [])
    if any(a.get("amount", 0) < 0 for a in allocs):
        return breach("no_conflict", "negative allocation amount")
    parties = [a.get("party_id") for a in allocs]
    if len(parties) != len(set(parties)):
        return breach("no_conflict", "a party is allocated more than once")
    return valid("no_conflict")


def priority_order(packet, P=None):
    c = section(packet, "clearing")
    allocs = c.get("allocations", [])
    requests = c.get("requests", [])
    served = {a.get("party_id"): a.get("amount", 0) for a in allocs}
    served_priorities = [_prio_of(requests, pid) for pid, amt in served.items() if amt > 0]
    # hard inversion: a fully denied requester outranks some served party
    for r in requests:
        pid, rp = r.get("party_id"), r.get("priority", 0)
        if served.get(pid, 0) == 0 and any(rp > sp for sp in served_priorities):
            return breach("priority_order", f"higher-priority party {pid} denied while lower served")
    # soft inversion: an underserved requester outranks some served party
    for r in requests:
        pid, rp = r.get("party_id"), r.get("priority", 0)
        got, want = served.get(pid, 0), r.get("amount", 0)
        if 0 < got < want and any(rp > sp for sp in served_priorities):
            return thin("priority_order", f"higher-priority party {pid} underserved while lower served")
    return valid("priority_order")


def clearing_integrity(packet, P=None):
    allocs = section(packet, "clearing").get("allocations", [])
    if not allocs:
        return breach("clearing_integrity", "no allocations in clearing result")
    bad = [a for a in allocs if not a.get("party_id") or a.get("amount") is None]
    if not bad:
        return valid("clearing_integrity")
    if len(bad) == len(allocs):
        return breach("clearing_integrity", "all allocations malformed")
    return thin("clearing_integrity", "some allocations missing party_id or amount")


MANIFEST = {
    "name": "reserve-flow", "version": "1.0",
    "predicates": ["conservation", "no_conflict", "priority_order", "clearing_integrity"],
    "packet_schema": "schemas/packet-clearing.schema.json",
    "source_project": "github.com/sadpig70/ReserveFlow",
}
PREDICATES = [conservation, no_conflict, priority_order, clearing_integrity]

_REQUESTS = [
    {"party_id": "A", "amount": 60, "priority": 3},
    {"party_id": "B", "amount": 50, "priority": 2},
    {"party_id": "C", "amount": 40, "priority": 1},
]


def _p(pid, allocations):
    return {"packet_id": pid, "subject": pid,
            "clearing": {"supply": 100, "allocations": allocations, "requests": _REQUESTS}}


SAMPLES = {
    # highest priorities filled first; only lowest (C) denied -> valid
    "valid": _p("RF-VALID-001", [{"party_id": "A", "amount": 60, "priority": 3},
                                 {"party_id": "B", "amount": 40, "priority": 2}]),
    # B (higher) underserved while C (lower) served -> soft inversion -> thin
    "thin": _p("RF-THIN-001", [{"party_id": "A", "amount": 60, "priority": 3},
                               {"party_id": "B", "amount": 30, "priority": 2},
                               {"party_id": "C", "amount": 10, "priority": 1}]),
    # A (highest) denied while B,C served -> hard inversion -> breach
    "breach": _p("RF-BREACH-001", [{"party_id": "B", "amount": 50, "priority": 2},
                                   {"party_id": "C", "amount": 40, "priority": 1}]),
}
