#!/usr/bin/env python3
"""SettleMeshPack — stablecoin settlement compliance pre-screen as Attestra predicates.

source_project: github.com/sadpig70/SettleMesh

ROUTING (HELIX machine-aware routing, NAME-vs-MACHINE correction): despite the name,
SettleMesh is NOT a Clearstra settlement (zero-sum payoff). It pre-screens one stablecoin
settlement intent against four independent compliance rules (reserve / aml / jurisdiction /
limit) and aggregates them into clear / review / block — a max-severity predicate gate,
which is Attestra's machine (clear/review/block ≅ valid/thin/breach). So the loop's
registry placement under Clearstra is corrected here: SettleMesh lands on Attestra. (The
mirror of AgentMesh, which the same routing pushed FROM Attestra TO Clearstra.)

Reproduces SettleMesh.screen incl. its published reference tables. See
tests/test_settle_mesh_parity.py.
"""

from ._base import valid, thin, breach

# Published reference tables (mirror SettleMesh.models). Indicative demo data.
ASSET_RESERVES = {  # asset -> (reserve_ratio, required_ratio)
    "usdc": (1.00, 1.00), "usdt": (1.00, 1.00), "pyusd": (1.00, 1.00), "eurc": (1.00, 1.00),
    "demo_undercollateralized": (0.92, 1.00),
}
SANCTIONS = {"sanctioned-entity-x", "ofac-demo-001", "blocked-wallet-0xdead"}
HIGH_RISK_PURPOSES = {"gambling", "mixing", "unregistered_exchange", "darkpool"}
BLOCKED_CORRIDORS = {("US", "KP"), ("EU", "KP"), ("US", "IR"), ("KR", "KP")}
RESTRICTED_CORRIDORS = {("US", "XX"), ("EU", "XX"), ("KR", "XX")}
KYC_LIMITS = {0: 1_000.0, 1: 10_000.0, 2: 100_000.0, 3: 1_000_000.0}


def _intent(packet):
    return packet.get("intent", {}) if isinstance(packet.get("intent"), dict) else {}


def reserve(packet, P=None):
    """Stablecoin must be fully reserved. Mirrors _reserve_check (unknown asset -> block,
    matching the source's validate-error path)."""
    asset = _intent(packet).get("asset")
    if asset not in ASSET_RESERVES:
        return breach("reserve", f"unknown asset '{asset}'")
    ratio, required = ASSET_RESERVES[asset]
    if ratio < required:
        return breach("reserve", f"asset '{asset}' is under-reserved ({ratio} < required {required})")
    return valid("reserve")


def aml(packet, P=None):
    """Sanctions -> block; high-risk purpose -> review. Mirrors _aml_check (worst finding)."""
    intent = _intent(packet)
    hits = [p for p in (intent.get("sender"), intent.get("receiver")) if p in SANCTIONS]
    if hits:
        return breach("aml", f"sanctioned party in settlement: {', '.join(hits)}")
    if intent.get("purpose", "general") in HIGH_RISK_PURPOSES:
        return thin("aml", f"high-risk purpose '{intent.get('purpose')}' requires review")
    return valid("aml")


def jurisdiction(packet, P=None):
    """Blocked corridor -> block; restricted corridor -> review. Mirrors _jurisdiction_check."""
    intent = _intent(packet)
    corridor = (intent.get("sender_jurisdiction"), intent.get("receiver_jurisdiction"))
    if corridor in BLOCKED_CORRIDORS:
        return breach("jurisdiction", f"corridor {corridor[0]}->{corridor[1]} is blocked")
    if corridor in RESTRICTED_CORRIDORS:
        return thin("jurisdiction", f"corridor {corridor[0]}->{corridor[1]} is restricted")
    return valid("jurisdiction")


def limit(packet, P=None):
    """Amount vs KYC-tier ceiling: over ceiling -> block at tier 0, else review. Mirrors _limit_check."""
    intent = _intent(packet)
    tier = intent.get("sender_kyc_tier", 0)
    if tier not in KYC_LIMITS:
        return breach("limit", f"unknown KYC tier {tier}")
    ceiling = KYC_LIMITS[tier]
    amount = float(intent.get("amount", 0) or 0)
    if amount > ceiling:
        if tier <= 0:
            return breach("limit", f"amount {amount:g} exceeds tier-0 ceiling {ceiling:g}; KYC required")
        return thin("limit", f"amount {amount:g} exceeds tier-{tier} ceiling {ceiling:g}")
    return valid("limit")


MANIFEST = {
    "name": "settle-mesh", "version": "1.0",
    "predicates": ["reserve", "aml", "jurisdiction", "limit"],
    "packet_schema": "schemas/packet-settlemesh.schema.json",
    "source_project": "github.com/sadpig70/SettleMesh",
}

PREDICATES = [reserve, aml, jurisdiction, limit]


def _packet(pid, intent):
    return {"packet_id": pid, "subject": pid, "intent": intent}


def _intent_doc(asset="usdc", amount=500.0, sender="alice", receiver="bob",
                sj="US", rj="EU", tier=1, purpose="general"):
    return {"intent_id": "i", "asset": asset, "amount": amount, "sender": sender, "receiver": receiver,
            "sender_jurisdiction": sj, "receiver_jurisdiction": rj, "sender_kyc_tier": tier, "purpose": purpose}


SAMPLES = {
    # fully reserved, no sanctions, clean corridor, within limit -> clear
    "valid": _packet("SET-V", _intent_doc()),
    # high-risk purpose (aml review), nothing blocked -> review
    "thin": _packet("SET-T", _intent_doc(purpose="gambling")),
    # sanctioned receiver -> block
    "breach": _packet("SET-B", _intent_doc(receiver="ofac-demo-001")),
}
