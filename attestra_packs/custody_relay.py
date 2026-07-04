#!/usr/bin/env python3
"""CustodyRelayPack — prove custody, integrity, and relay policy for offline handoffs.

source_project: github.com/sadpig70/CustodyRelayDocket
"""

from ._base import valid, thin, breach, section


def custody_chain(packet, P=None):
    r = section(packet, "relay")
    chain = r.get("chain", [])
    if len(chain) >= 2 and r.get("chain_continuous") is True:
        return valid("custody_chain")
    return breach("custody_chain", "custody chain is broken or too short")


def integrity_hash(packet, P=None):
    r = section(packet, "relay")
    send_hash, recv_hash = r.get("send_hash"), r.get("recv_hash")
    if not send_hash or not recv_hash:
        return thin("integrity_hash", "send or receive digest missing")
    if send_hash != recv_hash:
        return breach("integrity_hash", "artifact digest mismatch across relay")
    return valid("integrity_hash")


def relay_policy(packet, P=None):
    r = section(packet, "relay")
    if r.get("relay_route") in set(r.get("allowed_routes", [])):
        return valid("relay_policy")
    return breach("relay_policy", "relay route outside policy")


MANIFEST = {
    "name": "custody-relay", "version": "1.0",
    "predicates": ["custody_chain", "integrity_hash", "relay_policy"],
    "packet_schema": "schemas/packet-custody.schema.json",
    "source_project": "github.com/sadpig70/CustodyRelayDocket",
}
PREDICATES = [custody_chain, integrity_hash, relay_policy]


def _p(pid, chain, continuous, send_hash, recv_hash, route):
    return {"packet_id": pid, "subject": pid,
            "relay": {"chain": chain, "chain_continuous": continuous,
                      "send_hash": send_hash, "recv_hash": recv_hash,
                      "relay_route": route, "allowed_routes": ["R-1", "R-2"]}}


SAMPLES = {
    "valid": _p("CR-VALID-001", ["a", "b"], True, "h1", "h1", "R-1"),
    "thin": _p("CR-THIN-001", ["a", "b"], True, "h1", "", "R-1"),
    "breach": _p("CR-BREACH-001", ["a", "b"], True, "h1", "h2", "R-1"),
}
