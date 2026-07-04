# Attestra Architecture

> **One deterministic verdict kernel + N domain packs.** Attestra ingests a compact
> public evidence packet, runs a pack's predicate gates over it, aggregates a
> `valid`/`thin`/`breach` verdict, records it on a hash-chained audit ledger, and —
> for non-breach verdicts — issues a verifiable, revocable attestation.

## Layers

```
              ┌───────────────────────── meta / IO layer (file I/O, injected `now`) ─────────────────────────┐
   cli.py     attestra_pipeline.py     attestra_audit.py     attestra_helix.py
   (subcmds)  (multi-pack compose)     (closed audit loop)   (HELIX read-only bridge)
              └───────────────────────────────────────────────────────────────────────────────────────────┘
                                             │ calls
   ┌──────────────────────────────── attestra_packs/ (federated packs) ────────────────────────────────┐
   loader.py (discover · validate · fingerprint-dedup · load schema)      _base.py (predicate helpers)
   handback · spend-boundary · veto-escrow · delegation · withheld-action · policy-drift · custody-relay
   slot-gate · context-boundary · action-governance · repro-dossier · gen-cert · reserve-flow  (13 packs)
   └────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                             │ each pack contributes predicates only
   ┌──────────────────────────────── attestra_core/ (deterministic kernel) ────────────────────────────┐
   packet · verdict · gate_runtime · schema · ledger · fingerprint · provenance · attestation
   attestation_ledger · determinism           (stdlib only; no clock/network/AI; `now`/`sim` injected)
   └────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Kernel (`attestra_core/`)** — single source of truth. Verdict algebra, schema
  enforcement, ledgers, attestation issue/verify/revoke are defined **once** here. Packs
  never redefine them. Pure stdlib, fully deterministic.
- **Packs (`attestra_packs/`)** — each pack is one corpus project projected as a set of
  `predicate(packet, P) -> CheckResult` functions + a packet schema + samples. Packs are
  **federated**: tagged with `source_project` (github.com/sadpig70/*), never copied kernel logic.
- **Meta/IO layer** — orchestration and I/O (CLI, pipeline, audit, HELIX bridge). Reads/writes
  files and takes an injected `now`, but still performs no clock/network/random itself.

## Evaluation flow (`attestra_core/gate_runtime.py:run_gates`)

```
packet ─► validate_packet (private-payload reject + identifier)     ── fail ─► breach ("packet")
       ─► validate_against_schema (structural contract, if declared) ── fail ─► breach ("schema")
       ─► for each predicate: predicate(packet, P) -> CheckResult
       ─► aggregate_verdict (highest severity wins: valid < thin < breach)
       ─► result {subject, verdict, worst, checks, evaluated_at}
```

Separation of concerns: **schema = structure** (sections present, field types),
**predicates = evidence completeness + policy**. A packet that is structurally malformed
never reaches the predicates.

## Verdict → ledger → attestation

- `ledger.py` — append-only hash chain. `record_hash = sha256(canonical_json(record − {record_hash, recorded_at}))`,
  so `now`/`*_at` are metadata and the hash is time-independent; `verify_ledger` detects tampering.
- `attestation.py` — `issue_attestation` turns a non-breach result into a warrant
  (`valid`→`full`, `thin`→`conditional`; `breach`→`None`). `attestation_id` is a digest of the
  body, so re-issuing an identical result is idempotent. `verify_attestation` recomputes the id
  (tamper detection) and checks revocation.
- `attestation_ledger.py` — hash-chained `issue`/`revoke` events; `revoked_ids` drives verification.

## The three proven clusters

The `predicate(packet, P) -> CheckResult` contract has been validated across three
structurally-distinct corpus clusters, **all with zero kernel change**:

| Cluster | Packs | Shape |
|---|---|---|
| agent-action governance | handback, spend-boundary, veto-escrow, delegation, withheld-action, policy-drift, custody-relay, slot-gate, context-boundary, action-governance | single-subject evidence |
| provenance / trust | repro-dossier, gen-cert | single-subject evidence |
| clearing / market | reserve-flow | multi-party allocation as evidence; **subject = the clearing round** |

Clearing **verification** fits the contract; clearing **computation** (the matching engine) is
out of scope — it produces the packet and lives in the source project (see
[`.pgf/DESIGN-AttestraPacks.md §4`](../.pgf/DESIGN-AttestraPacks.md)). No `ClearingContract` needed.

## HELIX lineage & bridge

Attestra is a child of [HELIX](../../README.md) but runs standalone. `attestra_helix.py`
is an **optional, read-only** adapter: pointed at a HELIX root it reads exploit-state handback
packets (byte-identical to Attestra handback packets — the reference-pack parity pays off) and the
recreate registry, attests them, and writes ledgers/attestations **Attestra-side only**. HELIX is
never modified.

## Determinism boundary

See [DETERMINISM.md](DETERMINISM.md). In short: kernel + pack predicates are pure stdlib with
injected `now`/`sim`; `attestra_core/determinism.py` enforces this by scanning for clock/network/
random usage (`attestra determinism` → clean).

## Extending

See [PACK-CONTRACT.md](PACK-CONTRACT.md) — adding a pack is a manifest + predicates + schema +
samples file, with **no kernel change**.
