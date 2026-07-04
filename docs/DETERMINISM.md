# Attestra Determinism Boundary

> Attestra's verdicts and attestations must be **reproducible**: the same input yields the
> same output on any machine, at any time. This is a hard contract, enforced by a checker,
> not a convention.

## The rule

**`attestra_core/` and `attestra_packs/` are pure stdlib and fully deterministic.** They must not:

- read the clock (`time.time`, `time.monotonic`, `datetime.now`, `datetime.utcnow`, `date.today`, …)
- use randomness (`random`, `secrets`)
- touch the network (`socket`, `requests`, `urllib`, `http`, `aiohttp`)
- depend on any non-stdlib package

Anything time-varying is **injected**:

- **`now`** — a timestamp string, passed in by the caller. It only ever appears as metadata
  (`evaluated_at`, `recorded_at`, `issued_at`) and is **excluded from every hash**. So a verdict
  or ledger record computed at two different times is byte-identical.
- **`sim`** — a semantic-similarity function, injected where meaning comparison is needed. Embeddings
  and LLMs are the caller's responsibility, outside this boundary.

Parsing a date is fine (`datetime.fromisoformat` in `handback.py`) — that reads no clock. Only
*reading the current time* is forbidden.

## Why hashes are time-independent

Every ledger record hashes its content **minus** wall-time metadata:

```
record_hash = sha256(canonical_json(record − {record_hash, recorded_at}))
canonical_json = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

So `now` never enters a hash. `attestation_id` is likewise a digest of the attestation body
excluding `attestation_id` and `issued_at`. Re-running an audit with a different `now` produces
identical `record_hash`/`attestation_id` values (covered by tests).

## The checker

`attestra_core/determinism.py` walks the AST of every `.py` file under `attestra_core/` and
`attestra_packs/` and flags forbidden imports and calls.

```bash
python cli.py determinism        # -> {"clean": true, "files_scanned": N, "violations": {}}
```

`clean: true` is a release gate. If you add a pack or kernel code that reads the clock or the
network, this fails and names the file + line.

## Layer boundaries

| Layer | Files | Rule |
|---|---|---|
| **Kernel** | `attestra_core/*` | pure stdlib, deterministic, `now`/`sim` injected — **scanned** |
| **Packs** | `attestra_packs/*` | pure predicates, deterministic — **scanned** |
| **Meta / IO** | `cli.py`, `attestra_pipeline.py`, `attestra_audit.py`, `attestra_helix.py` | file I/O + injected `now` allowed; still no clock/network/random — not scanned, but keep clock-free |
| **Domain stage** | the pack's source project (e.g. a clearing engine, an LLM step) | **outside** the boundary — produces the packet; not part of Attestra |

The domain stage is where non-determinism legitimately lives (a matching engine, an embedding
model, an LLM). It runs *before* Attestra and hands Attestra a finished evidence packet. Attestra's
job — from packet to verdict to attestation — is the deterministic part.

## Practical guidance for pack authors

- Never call `datetime.now()` in a predicate. If you need "is this expired?", compare an
  injected/known time already present in the packet (as `handback.py` does with `handback_time`).
- Never seed behavior with `random`. If you need variation, it belongs in the domain stage that
  builds the packet, not in the verdict.
- Keep predicates pure: same packet in → same CheckResult out, forever.
- Run `python cli.py determinism` before committing. It is part of the release gate.
