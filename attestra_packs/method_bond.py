#!/usr/bin/env python3
"""MethodBondPack — method/model trust-bundle gate as Attestra predicates.

source_project: github.com/sadpig70/MethodBond

ROUTING (HELIX BUILD_ON_PLATFORM, machine-aware): MethodBond asks "is a published method
or model artifact properly licensed, independently reproducible, and certified against
its declared behavior baseline?" — three checks composed into certified / conditional /
rejected, a verdict gate that maps to Attestra's valid / thin / breach.

PARITY NOTE — the composition is asymmetric (not plain max-severity of three equal
checks): a license OR reproducibility failure is rejected, but a certification drift with
license+repro OK is only conditional. Reproduced by weighting the predicates so their
max-severity equals engine._compose_verdict: license/reproducibility fail -> breach,
certification fail -> thin. See tests/test_method_bond_parity.py.
"""

from ._base import valid, thin, breach

ALLOWED_TRANSFER_TYPES = {"exclusive", "non-exclusive", "permissive", "copyleft"}
ALLOWED_SOURCE_DOMAINS = {"academia", "industry", "government", "open", "unknown"}
ALLOWED_TARGET_INDUSTRIES = {"health", "finance", "energy", "education", "general", "unknown"}
REQUIRED_LICENSE_FIELDS = {"transfer_type", "source_domain", "target_industry", "revenue_share_pct"}
REQUIRED_PROVENANCE_FIELDS = {"input_hash", "output_hash", "build_command", "builder_id"}


def _license_errors(doc):
    if not isinstance(doc, dict):
        return ["license block must be an object"]
    errors = []
    missing = REQUIRED_LICENSE_FIELDS - set(doc.keys())
    if missing:
        errors.append(f"missing required fields: {sorted(missing)}")
    if doc.get("transfer_type") is not None and doc["transfer_type"] not in ALLOWED_TRANSFER_TYPES:
        errors.append(f"transfer_type '{doc['transfer_type']}' not in allowed set")
    if doc.get("source_domain") is not None and doc["source_domain"] not in ALLOWED_SOURCE_DOMAINS:
        errors.append(f"source_domain '{doc['source_domain']}' not in allowed set")
    if doc.get("target_industry") is not None and doc["target_industry"] not in ALLOWED_TARGET_INDUSTRIES:
        errors.append(f"target_industry '{doc['target_industry']}' not in allowed set")
    revenue = doc.get("revenue_share_pct")
    if revenue is not None:
        try:
            if not (0.0 <= float(revenue) <= 100.0):
                errors.append("revenue_share_pct must be between 0 and 100")
        except (TypeError, ValueError):
            errors.append("revenue_share_pct must be numeric")
    return errors


def _repro_errors(provenances):
    if not isinstance(provenances, list):
        return ["provenances must be a list"]
    if len(provenances) < 2:
        return ["at least two independent provenances are required"]
    errors = []
    output_hashes = []
    for idx, prov in enumerate(provenances):
        if not isinstance(prov, dict):
            errors.append(f"provenance[{idx}] must be an object")
            continue
        miss = REQUIRED_PROVENANCE_FIELDS - set(prov.keys())
        if miss:
            errors.append(f"provenance[{idx}] missing fields: {sorted(miss)}")
        if prov.get("output_hash") is not None:
            output_hashes.append(str(prov["output_hash"]))
    if len(output_hashes) < 2:
        errors.append("insufficient output hashes to compare")
        return errors
    if len(set(output_hashes)) != 1:
        errors.append("output hashes do not match across provenances")
        return errors
    return errors


def _cert_drifts(baseline, candidate):
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        return ["baseline_policy and candidate_policy must be objects"]
    base_rules, cand_rules = baseline.get("rules", {}), candidate.get("rules", {})
    if not isinstance(base_rules, dict) or not isinstance(cand_rules, dict):
        return ["policy.rules must be objects"]
    if not base_rules:
        return ["baseline policy has no rules"]
    drifts = []
    for key, base_val in base_rules.items():
        cand_val = cand_rules.get(key)
        if cand_val is None:
            drifts.append(f"missing rule '{key}' in candidate")
        elif cand_val != base_val:
            drifts.append(f"rule '{key}' drift: baseline={base_val!r} candidate={cand_val!r}")
    for key in cand_rules:
        if key not in base_rules:
            drifts.append(f"extra rule '{key}' in candidate (recoverable)")
    return drifts


def license(packet, P=None):
    """MLX-style license metadata — a failure rejects the bundle."""
    errors = _license_errors(packet.get("license", {}))
    return breach("license", "; ".join(errors)) if errors else valid("license", "license valid")


def reproducibility(packet, P=None):
    """ReproDossier-style cross-provenance reproducibility — a failure rejects."""
    errors = _repro_errors(packet.get("provenances", []))
    return breach("reproducibility", "; ".join(errors)) if errors else valid("reproducibility", "reproducible")


def certification(packet, P=None):
    """CertMesh-style baseline-vs-candidate conformance — drift is only conditional."""
    drifts = _cert_drifts(packet.get("baseline_policy", {}), packet.get("candidate_policy", {}))
    return thin("certification", "; ".join(drifts)) if drifts else valid("certification", "baseline clean")


MANIFEST = {
    "name": "method-bond", "version": "1.0",
    "predicates": ["license", "reproducibility", "certification"],
    "packet_schema": "schemas/packet-methodbond.schema.json",
    "source_project": "github.com/sadpig70/MethodBond",
}

PREDICATES = [license, reproducibility, certification]

_LICENSE_OK = {"transfer_type": "permissive", "source_domain": "open",
               "target_industry": "general", "revenue_share_pct": 10}
_PROV_OK = [
    {"input_hash": "i1", "output_hash": "h1", "build_command": "make", "builder_id": "b1"},
    {"input_hash": "i2", "output_hash": "h1", "build_command": "make", "builder_id": "b2"},
]


def _packet(pid, license_doc, provenances, baseline, candidate):
    return {"packet_id": pid, "subject": pid, "license": license_doc,
            "provenances": provenances, "baseline_policy": baseline, "candidate_policy": candidate}


SAMPLES = {
    # license valid, reproducible, baseline clean -> certified
    "valid": _packet("MB-V", _LICENSE_OK, _PROV_OK,
                     {"rules": {"max_temp": 100}}, {"rules": {"max_temp": 100}}),
    # license+repro OK, but candidate adds a rule (cert drift) -> conditional
    "thin": _packet("MB-T", _LICENSE_OK, _PROV_OK,
                    {"rules": {"max_temp": 100}}, {"rules": {"max_temp": 100, "extra": 1}}),
    # license missing required fields -> rejected
    "breach": _packet("MB-B", {}, _PROV_OK,
                      {"rules": {"max_temp": 100}}, {"rules": {"max_temp": 100}}),
}
