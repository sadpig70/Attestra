"""Attestra kernel — single-source deterministic verdict/attestation substrate.

stdlib only. Time is injected (`now`), semantic similarity is injected (`sim`).
Pack internal LLM/heuristic stages live outside this boundary (meta-layer).
"""

from .verdict import (
    SEVERITY, valid, thin, breach, missing, thin_or_breach, aggregate_verdict,
)
from .packet import (
    PRIVATE_FIELDS, validate_packet, has_private_payload, find_private_fields, subject_id,
)
from .gate_runtime import run_gates
from .ledger import (
    canonical_json, sha256, append_record, build_record, verify_ledger, last_record_hash,
)
from .fingerprint import normalize, tokenize, fingerprint, fingerprint_pack
from .provenance import trace_provenance, digest_checks
from .attestation import issue_attestation, verify_attestation, recompute_attestation_id
from .attestation_ledger import (
    record_issue, record_revoke, revoked_ids, verify_attestation_ledger, list_events,
)
from .schema import validate_against_schema, load_schema

__all__ = [
    "SEVERITY", "valid", "thin", "breach", "missing", "thin_or_breach", "aggregate_verdict",
    "PRIVATE_FIELDS", "validate_packet", "has_private_payload", "find_private_fields", "subject_id",
    "run_gates",
    "canonical_json", "sha256", "append_record", "build_record", "verify_ledger", "last_record_hash",
    "normalize", "tokenize", "fingerprint", "fingerprint_pack",
    "trace_provenance", "digest_checks",
    "issue_attestation", "verify_attestation", "recompute_attestation_id",
    "record_issue", "record_revoke", "revoked_ids", "verify_attestation_ledger", "list_events",
    "validate_against_schema", "load_schema",
]
