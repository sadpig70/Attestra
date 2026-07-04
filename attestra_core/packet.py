#!/usr/bin/env python3
"""Evidence packet model + private-payload rejection.

The one universal invariant across every pack: a packet carries only public
evidence digests, never private payloads. Pack-specific required sections are
checked by that pack's predicates, not here.
"""

PRIVATE_FIELDS = {
    "payload", "private_payload", "raw_payload",
    "secret", "secrets", "credential", "credentials",
}


def find_private_fields(value, private=PRIVATE_FIELDS, path=()):
    """Recursively collect dotted paths of any private field present (deterministic)."""
    found = []
    if isinstance(value, dict):
        for key, sub in sorted(value.items(), key=lambda kv: str(kv[0])):
            here = path + (str(key),)
            if str(key).lower() in private:
                found.append(".".join(here))
            found.extend(find_private_fields(sub, private, here))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found.extend(find_private_fields(item, private, path + (str(i),)))
    return found


def has_private_payload(value, private=PRIVATE_FIELDS):
    return bool(find_private_fields(value, private))


def validate_packet(packet, id_field="packet_id"):
    """Validate an evidence packet before predicates run.

    Universal checks only: must be a dict, must carry an identifier, and must not
    contain any private payload field. Returns {ok, reason, fields}.
    """
    if not isinstance(packet, dict):
        return {"ok": False, "reason": "packet_not_object", "fields": []}
    leaked = find_private_fields(packet)
    if leaked:
        return {"ok": False, "reason": "private_payload_present", "fields": leaked}
    ident = packet.get(id_field) or packet.get("packet_id") or packet.get("subject")
    if not ident:
        return {"ok": False, "reason": f"missing_identifier:{id_field}", "fields": []}
    return {"ok": True, "reason": "", "fields": []}


def subject_id(packet, id_field="packet_id"):
    return packet.get(id_field) or packet.get("packet_id") or packet.get("subject") or ""
