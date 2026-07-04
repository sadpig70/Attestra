# Changelog

All notable changes to Attestra are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); dates are ISO-8601.

## [0.1.0] — 2026-07-05

First release of Attestra — a deterministic verdict/attestation platform:
one stdlib kernel + N domain packs.

### Kernel (`attestra_core/`)
- Evidence packet model with private-payload rejection (`packet.py`)
- Verdict severity algebra `valid < thin < breach`, highest-severity aggregation (`verdict.py`)
- Gate runtime: packet check → schema check → predicates → aggregate (`gate_runtime.py`)
- Minimal deterministic JSON Schema validator + per-pack schema enforcement (`schema.py`)
- Hash-chained, tamper-evident, time-independent audit ledger (`ledger.py`)
- Identity/fingerprint primitive for pack dedup (`fingerprint.py`)
- Provenance trace (`provenance.py`)
- Attestation lifecycle: issue → verify → revoke (`attestation.py`, `attestation_ledger.py`)
- Determinism boundary checker (`determinism.py`)

### Packs (`attestra_packs/`) — 13 across 3 structurally-distinct clusters, all zero-kernel-change
- Governance (10): handback (reference, ActionHandbackVerifier parity), spend-boundary,
  veto-escrow, delegation, withheld-action, policy-drift, custody-relay, slot-gate,
  context-boundary, action-governance
- Provenance/trust (2): repro-dossier, gen-cert
- Clearing/market (1): reserve-flow (clearing **verification**; computation is out of scope)

### Orchestration & operations
- `attestra_pipeline.py` — multi-pack composition (generalizes SpendBoundary's recombination)
- `attestra_audit.py` — closed audit loop: batch ingest → route → verdict → attest → ledger → verify
- `attestra_helix.py` — optional read-only HELIX bridge (attest real HELIX corpus artifacts)
- `cli.py` — `sample / run / verify / verify-attestation / revoke-attestation / report /
  attest / pack / audit / helix-audit / determinism`

### Contracts & docs
- 5 kernel schemas + 13 per-pack packet schemas (`schemas/`)
- `docs/ARCHITECTURE.md`, `docs/PACK-CONTRACT.md`, `docs/DETERMINISM.md`
- Design under `.pgf/` (DESIGN/WORKPLAN/status) + `.pgxf/INDEX-Attestra.json`; roadmap in
  `.pgf/WORKPLAN-Attestra-Roadmap.md`

### Guarantees
- Determinism boundary enforced: kernel + packs are pure stdlib, `now`/`sim` injected,
  hashes exclude wall-time metadata (`attestra determinism` → clean)
- Full test suite green (`python -m unittest discover -s tests`)
