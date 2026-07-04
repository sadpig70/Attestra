#!/usr/bin/env python3
"""HELIX bridge — attest real HELIX corpus artifacts (read-only adapter).

Optional adapter: Attestra stays standalone; this only activates when pointed at a
HELIX root. It READS HELIX exploit-state handback packets and the recreate registry
(never writes into helix_root), runs handback packets through Attestra's handback
pack, and emits verdicts + verifiable/revocable attestations + an audit ledger.

Confirmed: a HELIX handback packet is byte-identical in shape to an Attestra handback
packet, so the mapping is the identity — the reference-pack parity pays off directly.
Ledgers/attestations are written to Attestra-side paths, keeping HELIX untouched.
Meta/IO layer (like cli.py): file I/O + injected `now`, clock/network-free.
"""

import json
import os

from attestra_core.gate_runtime import run_gates
from attestra_core.ledger import append_record, verify_ledger
from attestra_core.attestation import issue_attestation
from attestra_core.attestation_ledger import record_issue, verify_attestation_ledger
from attestra_packs.loader import get_pack

HANDBACK_KEYS = {"handback_id", "delegation", "custody", "route", "rollback", "trace"}
_EXPLOIT_STATE = ("examples", "exploit_state")
_REGISTRY_RELPATHS = (".recreate/registry.json", "examples/exploit_state/registry.json")


def is_handback_packet(obj):
    return isinstance(obj, dict) and HANDBACK_KEYS <= set(obj.keys())


def discover_handback_paths(helix_root):
    """Return sorted *.json paths under <helix_root>/examples/exploit_state (read-only)."""
    base = os.path.join(helix_root, *_EXPLOIT_STATE)
    if not os.path.isdir(base):
        return []
    return [os.path.join(base, n) for n in sorted(os.listdir(base)) if n.endswith(".json")]


def load_registry(helix_root):
    """Load the HELIX recreate registry if present. Returns (registry_or_None, path_or_None)."""
    for rel in _REGISTRY_RELPATHS:
        path = os.path.join(helix_root, *rel.split("/"))
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f), path
    return None, None


def registry_inventory(registry):
    """Project inventory from registry.generated_projects (dict keyed by project name)."""
    gp = (registry or {}).get("generated_projects", {})
    out = []
    if isinstance(gp, dict):
        for name, v in sorted(gp.items()):
            v = v if isinstance(v, dict) else {}
            out.append({
                "project": name, "status": v.get("status"),
                "semantic_family": v.get("semantic_family"), "archetype": v.get("archetype"),
                "verdict_scheme": v.get("verdict_scheme"), "repo_url": v.get("repo_url"),
            })
    return out


def helix_audit(helix_root, packs, ledger_path, now="", att_ledger=None, attest_out=None):
    """Attest every HELIX handback packet found under helix_root. HELIX is read-only.

    ledger_path / att_ledger / attest_out are Attestra-side; nothing is written into
    helix_root. Fresh ledgers each run so re-runs are idempotent.
    """
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
    if att_ledger and os.path.exists(att_ledger):
        os.remove(att_ledger)
    if attest_out:
        os.makedirs(attest_out, exist_ok=True)

    pack = get_pack(packs, "handback")
    entries, skipped = [], []
    by_verdict = {"valid": 0, "thin": 0, "breach": 0}

    for path in discover_handback_paths(helix_root):
        fname = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
        except (ValueError, OSError) as exc:
            skipped.append({"file": fname, "reason": f"invalid json: {exc}"})
            continue
        if not is_handback_packet(obj):
            skipped.append({"file": fname, "reason": "not a handback packet"})
            continue

        result = run_gates(obj, pack["predicate_fns"], now=now,
                           id_field="handback_id", schema=pack.get("schema"))
        result["pack"] = "handback"
        result["source_project"] = pack.get("source_project")
        rec = append_record(ledger_path, result, "handback", now=now)
        by_verdict[result["verdict"]] = by_verdict.get(result["verdict"], 0) + 1

        att = None
        if result["verdict"] != "breach":
            att = issue_attestation(
                result, chain={"pack": "handback", "source_project": pack.get("source_project")}, now=now)
            if att and att_ledger:
                record_issue(att_ledger, att, now=now)
            if att and attest_out:
                with open(os.path.join(attest_out, f"{att['attestation_id']}.json"),
                          "w", encoding="utf-8") as f:
                    json.dump(att, f, ensure_ascii=False, indent=2, sort_keys=True)
                    f.write("\n")
        entries.append({
            "file": fname, "handback_id": obj.get("handback_id"),
            "verdict": result["verdict"], "ledger_index": rec["index"],
            "attestation_id": att["attestation_id"] if att else None,
        })

    registry, reg_path = load_registry(helix_root)
    report = {
        "helix_root": helix_root, "handback_packets": len(entries),
        "by_verdict": by_verdict, "skipped": skipped,
        "attestations_issued": sum(1 for e in entries if e["attestation_id"]),
        "chain": verify_ledger(ledger_path),
        "registry_path": reg_path, "inventory": registry_inventory(registry),
        "entries": entries,
    }
    if att_ledger:
        report["att_chain"] = verify_attestation_ledger(att_ledger)
    return report


def render_helix_markdown(report):
    v = report["by_verdict"]
    lines = [
        f"# Attestra × HELIX Audit — {report['helix_root']}",
        "",
        f"- handback packets attested: {report['handback_packets']}",
        f"- verdicts: valid={v['valid']} thin={v['thin']} breach={v['breach']}",
        f"- attestations issued: {report['attestations_issued']}",
        f"- ledger chain valid: {report['chain']['valid']} ({report['chain']['records']} records)",
        f"- registry: `{report['registry_path']}` — {len(report['inventory'])} generated projects",
        "",
        "## Handback verdicts",
        "",
        "| # | handback_id | verdict | attestation |",
        "|---|---|---|---|",
    ]
    for e in report["entries"]:
        lines.append(f"| {e['ledger_index']} | {e['handback_id']} | {e['verdict']} | "
                     f"{e['attestation_id'] or '—'} |")
    if report["inventory"]:
        lines += ["", "## HELIX generated-project inventory (read-only)", "",
                  "| project | status | family | archetype | verdict_scheme |",
                  "|---|---|---|---|---|"]
        for it in report["inventory"]:
            lines.append(f"| {it['project']} | {it['status']} | {it['semantic_family']} | "
                         f"{it['archetype']} | {it['verdict_scheme']} |")
    lines.append("")
    return "\n".join(lines)
