#!/usr/bin/env python3
"""HandbackPack — reference pack. Faithful port of ActionHandbackVerifier.

source_project: github.com/sadpig70/ActionHandbackVerifier
Parity anchor: for the three canonical sample packets, run_gates over these five
predicates must yield the same aggregate verdict as evaluate_handback().
"""

import copy
import datetime as _dt
import re

from attestra_core.ledger import canonical_json, sha256
from attestra_core.packet import PRIVATE_FIELDS, has_private_payload
from ._base import valid, thin, breach, missing, thin_or_breach

_EVIDENCE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _parse_time(value):
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return _dt.datetime.fromisoformat(text)  # parsing only — not a clock read
    except ValueError:
        return None


def _expired(expires_at, handback_time):
    expires = _parse_time(expires_at)
    handback = _parse_time(handback_time)
    return bool(expires and handback and expires < handback)


def _is_sha256_hex(value):
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "")))


def _valid_evidence_path(value):
    text = str(value or "")
    if not text or text.startswith(("/", "\\")) or ".." in text.replace("\\", "/").split("/"):
        return False
    return bool(_EVIDENCE_PATH_RE.fullmatch(text)) and text.replace("\\", "/").startswith("evidence/")


def _bad_path(gate, evidence_path):
    if not _valid_evidence_path(evidence_path):
        return breach(gate, "invalid evidence path", evidence_path)
    return None


def _public_copy(value, omit_trace_digest=False, path=()):
    if isinstance(value, dict):
        return {
            k: _public_copy(v, omit_trace_digest, path + (str(k),))
            for k, v in sorted(value.items())
            if str(k).lower() not in PRIVATE_FIELDS
            and not (omit_trace_digest and path == ("trace",) and str(k) == "digest")
        }
    if isinstance(value, list):
        return [_public_copy(v, omit_trace_digest, path) for v in value]
    return value


def digest_public_surface(packet, omit_trace_digest=False):
    public = _public_copy(packet, omit_trace_digest=omit_trace_digest)
    return sha256(canonical_json(public))


def authority(packet, P=None):
    d = packet.get("delegation", {})
    miss = missing(["authority_id", "delegated_to", "action", "allowed_actions", "evidence_path"], d)
    if miss:
        return thin_or_breach("authority", miss)
    bad = _bad_path("authority", d.get("evidence_path"))
    if bad:
        return bad
    if d["action"] not in d.get("allowed_actions", []):
        return breach("authority", "action outside delegated authority", d.get("evidence_path"))
    if _expired(d.get("expires_at"), packet.get("handback_time")):
        return breach("authority", "delegation expired before handback", d.get("evidence_path"))
    return valid("authority", d.get("evidence_path"))


def custody(packet, P=None):
    c = packet.get("custody", {})
    miss = missing(["artifact_id", "from_actor", "to_actor", "handback_confirmed", "evidence_path"], c)
    if miss:
        return thin_or_breach("custody", miss)
    bad = _bad_path("custody", c.get("evidence_path"))
    if bad:
        return bad
    deleg = packet.get("delegation", {})
    delegated_to = deleg.get("delegated_to")
    return_to = deleg.get("return_to", deleg.get("authority_id"))
    if delegated_to and c.get("from_actor") != delegated_to:
        return breach("custody", "custody sender does not match delegated actor", c.get("evidence_path"))
    if return_to and c.get("to_actor") != return_to:
        return breach("custody", "custody receiver does not match return actor", c.get("evidence_path"))
    if c.get("handback_confirmed") is not True:
        return breach("custody", "handback not confirmed", c.get("evidence_path"))
    return valid("custody", c.get("evidence_path"))


def route(packet, P=None):
    r = packet.get("route", {})
    miss = missing(["planned_route_id", "actual_route_id", "status", "evidence_path"], r)
    if miss:
        return thin_or_breach("route", miss)
    bad = _bad_path("route", r.get("evidence_path"))
    if bad:
        return bad
    status = r.get("status")
    if status == "failed":
        return breach("route", "route check failed", r.get("evidence_path"))
    if status == "passed" and r.get("planned_route_id") != r.get("actual_route_id"):
        return breach("route", "passed route has planned/actual mismatch", r.get("evidence_path"))
    if status == "deviated" and r.get("rollback_required") is not True:
        return thin("route", "route deviated but rollback requirement is not declared", r.get("evidence_path"))
    if status not in ("passed", "deviated"):
        return thin("route", f"unknown route status: {status}", r.get("evidence_path"))
    return valid("route", r.get("evidence_path"))


def rollback(packet, P=None):
    rb = packet.get("rollback", {})
    miss = missing(["required", "completed", "evidence_path"], rb)
    if miss:
        return thin_or_breach("rollback", miss)
    bad = _bad_path("rollback", rb.get("evidence_path"))
    if bad:
        return bad
    if rb.get("required") is True and rb.get("completed") is not True:
        return breach("rollback", "required rollback not completed", rb.get("evidence_path"))
    if rb.get("required") is True and not rb.get("restoration_hash"):
        return thin("rollback", "rollback completed without restoration_hash", rb.get("evidence_path"))
    if rb.get("restoration_hash") and not _is_sha256_hex(rb.get("restoration_hash")):
        return breach("rollback", "restoration_hash is not sha256 hex", rb.get("evidence_path"))
    return valid("rollback", rb.get("evidence_path"))


def trace(packet, P=None):
    t = packet.get("trace", {})
    if has_private_payload(packet):
        return breach("trace", "packet contains private payload field", t.get("evidence_path", ""))
    if not t.get("digest") or not t.get("evidence_path"):
        return thin("trace", "trace digest or evidence_path missing", t.get("evidence_path", ""))
    bad = _bad_path("trace", t.get("evidence_path"))
    if bad:
        return bad
    if not _is_sha256_hex(t.get("digest")):
        return breach("trace", "trace digest is not sha256 hex", t.get("evidence_path"))
    if t.get("digest") != digest_public_surface(packet, omit_trace_digest=True):
        return breach("trace", "trace digest does not bind public surface", t.get("evidence_path"))
    return valid("trace", t.get("evidence_path"))


MANIFEST = {
    "name": "handback",
    "version": "1.0",
    "predicates": ["authority", "custody", "route", "rollback", "trace"],
    "packet_schema": "schemas/packet-handback.schema.json",
    "source_project": "github.com/sadpig70/ActionHandbackVerifier",
    "id_field": "handback_id",
}

PREDICATES = [authority, custody, route, rollback, trace]


def _base_packet():
    return {
        "handback_id": "HB-VALID-001",
        "handback_time": "2026-07-02T00:00:00+00:00",
        "delegation": {
            "authority_id": "AUTH-17", "delegated_to": "field-agent-7", "return_to": "AUTH-17",
            "action": "retrieve_artifact", "allowed_actions": ["retrieve_artifact", "return_to_base"],
            "expires_at": "2026-07-03T00:00:00+00:00",
            "evidence_path": "evidence/delegation/AUTH-17.json",
        },
        "custody": {
            "artifact_id": "ART-42", "from_actor": "field-agent-7", "to_actor": "AUTH-17",
            "handback_confirmed": True, "evidence_path": "evidence/custody/ART-42.json",
        },
        "route": {
            "planned_route_id": "ROUTE-A", "actual_route_id": "ROUTE-A", "status": "passed",
            "rollback_required": False, "evidence_path": "evidence/route/ROUTE-A.json",
        },
        "rollback": {"required": False, "completed": False,
                     "evidence_path": "evidence/rollback/not-required.json"},
        "trace": {"digest": "", "evidence_path": "evidence/trace/HB-VALID-001.sha256"},
    }


def _bind(packet):
    packet = copy.deepcopy(packet)
    packet["trace"]["digest"] = digest_public_surface(packet, omit_trace_digest=True)
    return packet


def _samples():
    v = _base_packet()

    t = copy.deepcopy(v)
    t["handback_id"] = "HB-THIN-001"
    t["route"]["status"] = "deviated"
    t["route"]["actual_route_id"] = "ROUTE-B"
    t["route"]["rollback_required"] = True
    t["rollback"]["required"] = True
    t["rollback"]["completed"] = True
    t["rollback"].pop("restoration_hash", None)

    b = copy.deepcopy(v)
    b["handback_id"] = "HB-BREACH-001"
    b["delegation"]["action"] = "open_restricted_zone"
    b["custody"]["handback_confirmed"] = False

    return {"valid": _bind(v), "thin": _bind(t), "breach": _bind(b)}


SAMPLES = _samples()
