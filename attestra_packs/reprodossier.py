#!/usr/bin/env python3
"""ReproDossier — verify reproducibility via output-hash agreement across builds.

source_project: github.com/sadpig70/ReproDossier
Cluster: provenance/trust (NOT agent-action governance) — a generalization probe
for the PackContract. Adds zero kernel change: manifest + predicates + schema only.
"""

from ._base import valid, thin, breach, section


def hash_agreement(packet, P=None):
    r = section(packet, "repro")
    hashes = [b.get("output_hash") for b in r.get("builds", []) if b.get("output_hash")]
    if len(hashes) < 2:
        return thin("hash_agreement", "not enough output hashes to compare")
    counts = {}
    for h in hashes:
        counts[h] = counts.get(h, 0) + 1
    if len(counts) == 1:
        return valid("hash_agreement")
    if max(counts.values()) > len(hashes) / 2:
        return thin("hash_agreement", "output hashes agree by majority, not unanimously")
    return breach("hash_agreement", "build output hashes disagree")


def provenance_count(packet, P=None):
    n = len(section(packet, "repro").get("builds", []))
    if n >= 3:
        return valid("provenance_count")
    if n == 2:
        return thin("provenance_count", "only two independent build provenances")
    return breach("provenance_count", "fewer than two independent build provenances")


def build_integrity(packet, P=None):
    builds = section(packet, "repro").get("builds", [])
    if not builds:
        return breach("build_integrity", "no build provenances present")
    incomplete = [b for b in builds if not b.get("build_id") or not b.get("output_hash")]
    if not incomplete:
        return valid("build_integrity")
    if len(incomplete) == len(builds):
        return breach("build_integrity", "all builds missing id or output hash")
    return thin("build_integrity", "some builds missing id or output hash")


MANIFEST = {
    "name": "repro-dossier", "version": "1.0",
    "predicates": ["hash_agreement", "provenance_count", "build_integrity"],
    "packet_schema": "schemas/packet-repro.schema.json",
    "source_project": "github.com/sadpig70/ReproDossier",
}
PREDICATES = [hash_agreement, provenance_count, build_integrity]


def _p(pid, builds):
    return {"packet_id": pid, "subject": pid, "repro": {"builds": builds, "required_agree": 2}}


SAMPLES = {
    "valid": _p("RD-VALID-001", [{"build_id": "B1", "output_hash": "h1"},
                                 {"build_id": "B2", "output_hash": "h1"},
                                 {"build_id": "B3", "output_hash": "h1"}]),
    "thin": _p("RD-THIN-001", [{"build_id": "B1", "output_hash": "h1"},
                               {"build_id": "B2", "output_hash": "h1"}]),
    "breach": _p("RD-BREACH-001", [{"build_id": "B1", "output_hash": "h1"},
                                   {"build_id": "B2", "output_hash": "h2"},
                                   {"build_id": "B3", "output_hash": "h3"}]),
}
