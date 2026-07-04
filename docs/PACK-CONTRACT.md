# Attestra Pack Contract

> How to author a new pack. A pack projects one domain (a HELIX corpus project, or your
> own) onto Attestra's verdict kernel. **Adding a pack requires no kernel change** —
> just one module + one schema.

## What a pack is

A pack is a Python module under `attestra_packs/` that exposes exactly three module-level names:

| Name | Type | Meaning |
|---|---|---|
| `MANIFEST` | `dict` | pack metadata (see below) |
| `PREDICATES` | `list[callable]` | the gate functions, each `predicate(packet, P) -> CheckResult` |
| `SAMPLES` | `dict[str, dict]` | at least `valid` / `thin` / `breach` example packets |

The loader (`attestra_packs/loader.py`) auto-discovers every module in the package
(except `loader` and `_base`), validates the contract, dedups by behavior fingerprint, and
loads the declared schema. No registration call is needed — drop the file in and it loads.

## MANIFEST

```python
MANIFEST = {
    "name": "my-pack",                       # unique pack name (kebab-case)
    "version": "1.0",
    "predicates": ["gate_a", "gate_b"],      # gate-key STRINGS (names of your CheckResult gates)
    "packet_schema": "schemas/packet-mypack.schema.json",  # repo-relative path (must exist)
    "source_project": "github.com/sadpig70/MyProject",     # provenance (federate, not copy)
    "id_field": "packet_id",                 # optional; the packet's identifier field (default "packet_id")
}
```

Required keys: `name`, `version`, `predicates`, `packet_schema`, `source_project`.
`predicates` holds the gate-key **strings** (used for the dedup fingerprint and `pack list`);
the callables go in `PREDICATES`. The loader **rejects** a pack whose `packet_schema` file is
missing (surfaced in `registry["errors"]`) — the contract is enforced, never dangling.

### Dedup by fingerprint

Two packs with the same predicate set + schema share a fingerprint
(`attestra_core/fingerprint.py:fingerprint_pack`, name-independent) and the duplicate is
dropped into `registry["dropped"]`. This prevents silent re-registration of recombinations.

## A predicate

```python
def predicate(packet: dict, P: dict) -> dict:  # returns a CheckResult
    ...
```

- **Pure function.** No side effects, no clock, no network, no randomness (see DETERMINISM.md).
  Ledger append and attestation issuance are the kernel's job, not the predicate's.
- Reads only from `packet` (and optional policy `P`). Returns a **CheckResult**.

### CheckResult

Build it with the helpers in `attestra_packs/_base.py` (never hand-roll the dict):

```python
from ._base import valid, thin, breach, missing, thin_or_breach, section, require

valid("gate_a")                          # {gate, verdict:"valid",  reason:"predicate satisfied", evidence_path, evidence_ok:True}
thin("gate_a", "evidence incomplete")    # verdict:"thin"
breach("gate_a", "policy violated")      # verdict:"breach"
```

Severity: `valid < thin < breach`. `run_gates` aggregates to the **highest** severity across all
predicates (order-independent), and a schema/packet failure short-circuits to `breach` before any
predicate runs.

### `_base` helpers

| Helper | Use |
|---|---|
| `section(packet, "name")` | get `packet["name"]` as a dict (empty dict if absent) |
| `require("gate", obj, ["f1","f2"])` | returns a thin/breach CheckResult if a field is missing, else `None` |
| `missing(fields, obj)` | list of absent/empty fields |
| `thin_or_breach("gate", missing)` | breach if `evidence_path` missing, else thin |
| `index_gap(order, current, target)` | positional gap in an ordered scope list |

## Packet & schema

A packet is a public evidence dict: an identifier (`packet_id`, or your `id_field`) plus
domain sections. **Private payload fields are rejected** by the kernel — never include
`payload`, `private_payload`, `raw_payload`, `secret`, `secrets`, `credential`, `credentials`.

The schema (`schemas/packet-mypack.schema.json`) is the **structural** contract only:
which sections exist and their field types. Leave evidence-completeness and policy to the
predicates. Supported keywords (`attestra_core/schema.py`): `type` (incl. unions), `properties`,
`required`, `enum`, `pattern`, `minimum`, `minItems`, `items`, `anyOf`, `not`, `additionalProperties`.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["packet_id", "my"],
  "properties": {
    "packet_id": {"type": "string"},
    "my": {"type": "object", "properties": {
      "score": {"type": "number"}, "flag": {"type": "boolean"}}}
  }
}
```

## Complete minimal example

`attestra_packs/example_min.py`:

```python
from ._base import valid, thin, breach, section, require

def threshold(packet, P=None):
    m = section(packet, "my")
    err = require("threshold", m, ["score"])
    if err:
        return err
    score = m["score"]
    if score >= 0.8:
        return valid("threshold")
    if score >= 0.5:
        return thin("threshold", "score in the soft band")
    return breach("threshold", "score below floor")

def flag(packet, P=None):
    return valid("flag") if section(packet, "my").get("flag") is True \
        else breach("flag", "flag not set")

MANIFEST = {
    "name": "example-min", "version": "1.0",
    "predicates": ["threshold", "flag"],
    "packet_schema": "schemas/packet-example.schema.json",
    "source_project": "github.com/sadpig70/Example",
}
PREDICATES = [threshold, flag]

def _p(pid, score, flag):
    return {"packet_id": pid, "subject": pid, "my": {"score": score, "flag": flag}}

SAMPLES = {
    "valid":  _p("EX-VALID-001", 0.9, True),
    "thin":   _p("EX-THIN-001",  0.6, True),
    "breach": _p("EX-BREACH-001", 0.1, True),
}
```

Drop that file plus `schemas/packet-example.schema.json` in place and the pack loads with **no
kernel change**. Verify:

```bash
python cli.py pack list                                   # example-min appears, 0 errors
python cli.py sample --pack example-min --out examples
python cli.py run --pack example-min --input examples/example-min.valid.json   # -> valid
```

## Checklist

- [ ] Module exposes `MANIFEST`, `PREDICATES`, `SAMPLES`
- [ ] `MANIFEST` has all required keys; `packet_schema` file exists
- [ ] Each predicate is pure (no clock/network/random/side effects) and returns a `_base` CheckResult
- [ ] Schema is structural only (sections + types); completeness/policy live in predicates
- [ ] No private-payload fields in any sample
- [ ] `SAMPLES` has `valid`/`thin`/`breach` that actually aggregate to those verdicts
- [ ] `python cli.py pack list` shows the pack with 0 errors; `determinism` stays clean
