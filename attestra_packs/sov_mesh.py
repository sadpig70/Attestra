#!/usr/bin/env python3
"""SovMeshPack — sovereignty architecture audit as an Attestra predicate gate.

source_project: github.com/sadpig70/SovMesh

CONDENSE FINDING (HELIX Condense): the "Compatibility Mesh" cluster (SovMesh, PqcMesh,
AgentMesh, SignalMesh, FlowMesh) shares a NAME (L11 interconnection-mesh transplant) but
NOT one machine — machine-aware routing verified each against real code and split them:
SovMesh/PqcMesh/SignalMesh reduce to a per-item assessment -> severity verdict (exactly
Attestra's predicate gate -> BUILD_ON_PLATFORM as packs); AgentMesh is pricing + cost
rollup with no verdict algebra (Clearstra's machine, NOT an Attestra pack). SovMesh's
{sovereign, conditional, breach} maps to {valid, thin, breach}. This pack reproduces
SovMesh.audit as five predicates (parity anchor).
"""

from ._base import valid, thin, breach

STRICT_CLASSES = {"restricted", "sovereign"}
_SEV = {"valid": 0, "thin": 1, "breach": 2}


def _worst(gate, items):
    """items: list of (severity, reason). Return the highest-severity CheckResult."""
    if not items:
        return valid(gate)
    sev, reason = max(items, key=lambda x: _SEV[x[0]])
    if sev == "breach":
        return breach(gate, reason)
    if sev == "thin":
        return thin(gate, reason)
    return valid(gate)


def _sec(packet):
    return packet["policy"], packet.get("components", [])


def residency(packet, P=None):
    policy, comps = _sec(packet)
    allowed = set(policy.get("allowed_jurisdictions", []))
    out = []
    for c in comps:
        if c.get("data_classification") == "public" or c.get("hosting_jurisdiction") in allowed:
            continue
        strict = c.get("data_classification") in STRICT_CLASSES
        out.append(("breach" if strict else "thin",
                    f"{c['data_classification']} data hosted in {c['hosting_jurisdiction']} outside allowed"))
    return _worst("residency", out)


def cross_border(packet, P=None):
    policy, comps = _sec(packet)
    allowed = set(policy.get("allowed_jurisdictions", []))
    out = []
    for c in comps:
        if policy.get("allow_cross_border") or c.get("data_classification") == "public":
            continue
        offending = [j for j in c.get("cross_border_replicas", []) if j not in allowed]
        if not offending:
            continue
        strict = c.get("data_classification") in STRICT_CLASSES
        out.append(("breach" if strict else "thin", f"data replicated cross-border to {offending}"))
    return _worst("cross_border", out)


def operator(packet, P=None):
    policy, comps = _sec(packet)
    allowed = set(policy.get("allowed_jurisdictions", []))
    out = []
    for c in comps:
        if c.get("data_classification") == "public" or c.get("provider_home_jurisdiction") in allowed:
            continue
        strict = c.get("data_classification") in STRICT_CLASSES
        if strict:
            if c.get("operator_access") and policy.get("prohibit_foreign_operator_access"):
                out.append(("breach", "foreign provider has cleartext operator access to strict data"))
            else:
                out.append(("thin", "residual exposure: foreign provider home jurisdiction"))
        elif c.get("operator_access"):
            out.append(("thin", "foreign provider has operator access to internal data"))
    return _worst("operator", out)


def provider(packet, P=None):
    policy, comps = _sec(packet)
    blocked = set(policy.get("blocked_provider_jurisdictions", []))
    out = []
    for c in comps:
        if c.get("data_classification") == "public":
            continue
        if c.get("provider_home_jurisdiction") in blocked:
            out.append(("breach", f"provider home {c['provider_home_jurisdiction']} is blocked"))
    return _worst("provider", out)


def key_control(packet, P=None):
    policy, comps = _sec(packet)
    if not policy.get("require_customer_managed_keys"):
        return valid("key_control")
    out = []
    for c in comps:
        if c.get("data_classification") in STRICT_CLASSES and not c.get("customer_managed_keys"):
            out.append(("breach", "strict data not protected by customer-managed keys"))
    return _worst("key_control", out)


MANIFEST = {
    "name": "sov-mesh", "version": "1.0",
    "predicates": ["residency", "cross_border", "operator", "provider", "key_control"],
    "packet_schema": "schemas/packet-sovmesh.schema.json",
    "source_project": "github.com/sadpig70/SovMesh",
}

PREDICATES = [residency, cross_border, operator, provider, key_control]


def _packet(pid, comps, allow_cross_border=False):
    return {"packet_id": pid, "subject": pid,
            "policy": {"allowed_jurisdictions": ["EU"], "allow_cross_border": allow_cross_border,
                       "prohibit_foreign_operator_access": True,
                       "blocked_provider_jurisdictions": ["XX"], "require_customer_managed_keys": True},
            "components": comps}


def _c(cid, cls, host, provider_home, op=False, cmk=True, replicas=None):
    return {"component_id": cid, "data_classification": cls, "hosting_jurisdiction": host,
            "provider_home_jurisdiction": provider_home, "operator_access": op,
            "customer_managed_keys": cmk, "cross_border_replicas": replicas or []}


SAMPLES = {
    "valid": _packet("SM-V", [_c("db", "restricted", "EU", "EU", cmk=True)]),
    "thin": _packet("SM-T", [_c("cache", "internal", "US", "US", op=True)]),      # foreign operator, internal -> conditional
    "breach": _packet("SM-B", [_c("db", "restricted", "US", "US", cmk=True)]),    # strict data hosted outside allowed -> breach
}
