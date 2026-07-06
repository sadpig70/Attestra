#!/usr/bin/env python3
"""PqcMeshPack — post-quantum migration posture as an Attestra predicate gate.

source_project: github.com/sadpig70/PqcMesh

CONDENSE FINDING (HELIX Condense): the "Compatibility Mesh" cluster (SovMesh, PqcMesh,
AgentMesh, SignalMesh, FlowMesh) shares a NAME but not one machine — machine-aware
routing splits it: SovMesh/PqcMesh/SignalMesh reduce to a per-item assessment ->
severity verdict (exactly Attestra's predicate gate -> BUILD_ON_PLATFORM as packs);
AgentMesh is pricing + cost rollup with no verdict algebra (Clearstra's machine, NOT an
Attestra pack). PqcMesh's per-asset verdict {quantum_safe/pqc_ready -> ok,
quantum_weakened -> caution, quantum_broken/classically_broken -> fail} maps to
{valid, thin, breach}. This pack reproduces PqcMesh.assess as predicates over a
crypto-asset inventory (parity anchor; see tests/test_pqc_mesh_parity.py which checks
it against the real PqcMesh when present).

Reference values (algorithm verdicts, quantum horizon) are the public NIST PQC figures
PqcMesh publishes as evidence (FIPS 203/204/205, 2024) — not a cryptographic audit.
"""

from ._base import valid, thin, breach

# Public reference: algorithm -> (quantum verdict, severity: 0 safe / 2 weakened / 3 broken).
# Mirrors PqcMesh.models.ALGORITHM_TABLE (the published NIST reference values).
_ALGORITHM = {
    "rsa1024": ("quantum_broken", 3), "rsa2048": ("quantum_broken", 3),
    "rsa4096": ("quantum_broken", 3), "ecdsa_p256": ("quantum_broken", 3),
    "ecdh_p256": ("quantum_broken", 3), "ecc_p384": ("quantum_broken", 3),
    "dh2048": ("quantum_broken", 3), "dsa2048": ("quantum_broken", 3),
    "aes128": ("quantum_weakened", 2), "3des": ("quantum_weakened", 2),
    "aes256": ("quantum_safe", 0), "sha256": ("quantum_safe", 0),
    "sha384": ("quantum_safe", 0), "sha512": ("quantum_safe", 0),
    "sha3_256": ("quantum_safe", 0),
    "md5": ("classically_broken", 3), "sha1": ("classically_broken", 3),
    "des": ("classically_broken", 3),
    "ml_kem_512": ("pqc_ready", 0), "ml_kem_768": ("pqc_ready", 0),
    "ml_dsa_65": ("pqc_ready", 0), "slh_dsa_128s": ("pqc_ready", 0),
}
_UNKNOWN = ("quantum_broken", 3)          # conservative: unrecognized -> assume broken
QUANTUM_HORIZON_YEARS = 10.0
_HARVESTABLE = {"confidentiality", "key_exchange"}

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


def _assets(packet):
    a = packet.get("assets", [])
    return [c for c in a if isinstance(c, dict)]


def quantum_verdict(algorithm):
    """(verdict, severity) for an algorithm. Unknown -> broken (conservative)."""
    return _ALGORITHM.get(algorithm, _UNKNOWN)


def algorithm_resilience(packet, P=None):
    """Each asset's algorithm vs a quantum adversary: broken -> breach, weakened -> thin."""
    out = []
    for a in _assets(packet):
        verdict, sev = quantum_verdict(a.get("algorithm", ""))
        if sev >= 3:
            out.append(("breach", f"{a.get('asset_id')} uses {a.get('algorithm')} ({verdict})"))
        elif sev == 2:
            out.append(("thin", f"{a.get('asset_id')} uses {a.get('algorithm')} ({verdict}); upgrade key size"))
    return _worst("algorithm_resilience", out)


def hndl_exposure(packet, P=None):
    """Harvest-now-decrypt-later: confidentiality/key_exchange data that outlives the
    quantum horizon while protected by a broken algorithm is exposed retroactively."""
    out = []
    for a in _assets(packet):
        verdict, sev = quantum_verdict(a.get("algorithm", ""))
        if verdict in ("quantum_safe", "pqc_ready"):
            continue
        if a.get("purpose") not in _HARVESTABLE:
            continue
        life = float(a.get("data_lifetime_years", 0) or 0)
        if sev >= 3 and life >= QUANTUM_HORIZON_YEARS:
            out.append(("breach", f"{a.get('asset_id')}: {life:g}y confidential data harvestable before PQC"))
        elif life >= QUANTUM_HORIZON_YEARS / 2:
            out.append(("thin", f"{a.get('asset_id')}: medium-term harvest-now-decrypt-later exposure"))
    return _worst("hndl_exposure", out)


def migration_accountability(packet, P=None):
    """A vulnerable asset must be crypto-agile or firmware-updatable to migrate in place;
    a stuck, long-lived, broken-crypto device is a breach (needs replacement/isolation)."""
    out = []
    for a in _assets(packet):
        verdict, sev = quantum_verdict(a.get("algorithm", ""))
        if sev == 0:
            continue
        if a.get("crypto_agile") or a.get("firmware_updatable"):
            continue
        dev_life = float(a.get("device_lifetime_years", 0) or 0)
        if sev >= 3 and dev_life >= 3:
            out.append(("breach",
                        f"{a.get('asset_id')}: broken crypto on non-updatable device (life {dev_life:g}y)"))
        else:
            out.append(("thin", f"{a.get('asset_id')}: not crypto-agile; plan replacement/isolation"))
    return _worst("migration_accountability", out)


MANIFEST = {
    "name": "pqc-mesh", "version": "1.0",
    "predicates": ["algorithm_resilience", "hndl_exposure", "migration_accountability"],
    "packet_schema": "schemas/packet-pqcmesh.schema.json",
    "source_project": "github.com/sadpig70/PqcMesh",
}

PREDICATES = [algorithm_resilience, hndl_exposure, migration_accountability]


def _packet(pid, assets):
    return {"packet_id": pid, "subject": pid, "assets": assets}


def _a(aid, algorithm, purpose="confidentiality", data_life=1, device_life=1,
       agile=True, updatable=True, owner="crypto-team"):
    return {"asset_id": aid, "owner": owner, "algorithm": algorithm, "purpose": purpose,
            "data_lifetime_years": data_life, "device_lifetime_years": device_life,
            "crypto_agile": agile, "firmware_updatable": updatable}


SAMPLES = {
    # all quantum-safe / pqc-ready -> valid
    "valid": _packet("PQC-V", [
        _a("kms", "ml_kem_768", "key_exchange"),
        _a("logs", "sha256", "integrity"),
        _a("bulk", "aes256", "confidentiality"),
    ]),
    # weakened algorithm, agile + short-lived -> caution only -> thin
    "thin": _packet("PQC-T", [
        _a("edge-cache", "aes128", "confidentiality", data_life=2, agile=True),
    ]),
    # broken algorithm on long-lived confidential data -> breach
    "breach": _packet("PQC-B", [
        _a("root-ca", "rsa2048", "signature", device_life=15, agile=False, updatable=False),
        _a("archive", "rsa4096", "confidentiality", data_life=25),
    ]),
}
