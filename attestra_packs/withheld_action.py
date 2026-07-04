#!/usr/bin/env python3
"""WithheldActionPack — justify withholding a high-risk release.

source_project: github.com/sadpig70/WithheldActionWitness
"""

from ._base import valid, thin, breach, section


def duty(packet, P=None):
    w = section(packet, "withholding")
    if w.get("duty_basis"):
        return valid("duty")
    return thin("duty", "no declared duty basis for withholding")


def exposure(packet, P=None):
    w = section(packet, "withholding")
    if w.get("exposure_doc"):
        return valid("exposure")
    return thin("exposure", "avoided exposure not documented")


def rollback(packet, P=None):
    w = section(packet, "withholding")
    if w.get("rollback_possible") is True:
        return valid("rollback")
    return breach("rollback", "withheld state is not rollback-able")


def authority(packet, P=None):
    w = section(packet, "withholding")
    if w.get("authority_valid") is True:
        return valid("authority")
    return breach("authority", "withholding authority not valid")


MANIFEST = {
    "name": "withheld-action", "version": "1.0",
    "predicates": ["duty", "exposure", "rollback", "authority"],
    "packet_schema": "schemas/packet-withheld.schema.json",
    "source_project": "github.com/sadpig70/WithheldActionWitness",
}
PREDICATES = [duty, exposure, rollback, authority]


def _p(pid, duty_basis, exposure_doc, rollback_possible, authority_valid):
    return {"packet_id": pid, "subject": pid,
            "withholding": {"duty_basis": duty_basis, "exposure_doc": exposure_doc,
                            "rollback_possible": rollback_possible,
                            "authority_valid": authority_valid}}


SAMPLES = {
    "valid": _p("WA-VALID-001", "duty/safety-review", "evidence/exposure/e1.json", True, True),
    "thin": _p("WA-THIN-001", "", "evidence/exposure/e1.json", True, True),
    "breach": _p("WA-BREACH-001", "duty/safety-review", "evidence/exposure/e1.json", False, True),
}
