#!/usr/bin/env python3
"""GenCert — prove the generator once at birth; artifacts inherit trust.

source_project: github.com/sadpig70/GenCert
Cluster: provenance/trust — second generalization probe for the PackContract.
Zero kernel change: manifest + predicates + schema only.
"""

from ._base import valid, thin, breach, section


def generator_cert(packet, P=None):
    g = section(packet, "gencert")
    if not g.get("cert_id"):
        return breach("generator_cert", "no generator certificate")
    if g.get("revoked") is True:
        return breach("generator_cert", "generator certificate revoked")
    return valid("generator_cert")


def lineage_binding(packet, P=None):
    g = section(packet, "gencert")
    gen = g.get("generator_id")
    if gen and g.get("artifact_generator_id") == gen:
        return valid("lineage_binding")
    return breach("lineage_binding", "artifact not bound to the certified generator")


def cert_scope(packet, P=None):
    g = section(packet, "gencert")
    scope = g.get("certified_scope", [])
    if not scope:
        return thin("cert_scope", "certified scope unspecified")
    if g.get("artifact_type") in scope:
        return valid("cert_scope")
    return breach("cert_scope", "artifact type outside the certified scope")


MANIFEST = {
    "name": "gen-cert", "version": "1.0",
    "predicates": ["generator_cert", "lineage_binding", "cert_scope"],
    "packet_schema": "schemas/packet-gencert.schema.json",
    "source_project": "github.com/sadpig70/GenCert",
}
PREDICATES = [generator_cert, lineage_binding, cert_scope]


def _p(pid, cert_id, revoked, gen, artifact_gen, artifact_type, scope):
    return {"packet_id": pid, "subject": pid,
            "gencert": {"cert_id": cert_id, "generator_id": gen, "revoked": revoked,
                        "artifact_generator_id": artifact_gen, "artifact_type": artifact_type,
                        "certified_scope": scope}}


SAMPLES = {
    "valid": _p("GC-VALID-001", "C1", False, "G1", "G1", "model", ["model", "dataset"]),
    "thin": _p("GC-THIN-001", "C1", False, "G1", "G1", "model", []),
    "breach": _p("GC-BREACH-001", "C1", True, "G1", "G1", "model", ["model"]),
}
