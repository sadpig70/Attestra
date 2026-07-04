#!/usr/bin/env python3
"""Attestra CLI — sample / run / verify / report / attest / pack / determinism.

stdlib only. `now` is injected via --now (default ""), never read from the clock,
so the whole tool is deterministic.
"""

import argparse
import json
import os
import sys

from attestra_core.gate_runtime import run_gates
from attestra_core.ledger import append_record, verify_ledger
from attestra_core.attestation import issue_attestation, verify_attestation
from attestra_core.attestation_ledger import (
    record_issue, record_revoke, revoked_ids, verify_attestation_ledger,
)
from attestra_core.determinism import check_tree
from attestra_packs.loader import load_packs, get_pack
from attestra_pipeline import run_pipeline
from attestra_audit import run_audit, render_audit_markdown

ROOT = os.path.dirname(os.path.abspath(__file__))


def _load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dump(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def _evaluate(registry, pack_name, packet, now):
    pack = get_pack(registry, pack_name)
    result = run_gates(packet, pack["predicate_fns"], now=now,
                       id_field=pack.get("id_field", "packet_id"),
                       schema=pack.get("schema"))
    result["pack"] = pack_name
    result["source_project"] = pack.get("source_project")
    return result


def cmd_sample(args, registry):
    pack = get_pack(registry, args.pack)
    os.makedirs(args.out, exist_ok=True)
    written = {}
    for name, packet in pack["samples"].items():
        path = os.path.join(args.out, f"{args.pack}.{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(packet, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        written[name] = path
    _dump({"pack": args.pack, "written": written})
    return 0


def cmd_run(args, registry):
    packet = _load_json(args.input)
    if args.pipeline:
        names = [n.strip() for n in args.pipeline.split(",") if n.strip()]
        result = run_pipeline(packet, names, registry, now=args.now)
    else:
        result = _evaluate(registry, args.pack, packet, args.now)
        if args.ledger:
            record = append_record(args.ledger, result, args.pack, now=args.now)
            result["ledger_record"] = {"index": record["index"], "record_hash": record["record_hash"]}
    _dump(result)
    return 0 if result["verdict"] != "breach" else 1


def cmd_attest(args, registry):
    packet = _load_json(args.input)
    result = _evaluate(registry, args.pack, packet, args.now)
    chain = {"pack": args.pack, "source_project": result.get("source_project")}
    att = issue_attestation(result, chain=chain, now=args.now)
    if att is None:
        _dump({"issued": False, "reason": "breach verdict — attestation refused",
               "verdict": result["verdict"]})
        return 1
    out = {"issued": True, "attestation": att}
    if args.att_ledger:
        rec = record_issue(args.att_ledger, att, now=args.now)
        out["att_ledger_index"] = rec["index"]
    _dump(out)
    return 0


def cmd_verify_attestation(args, _registry):
    att = _load_json(args.input)
    revoked = revoked_ids(args.ledger) if args.ledger else set()
    result = verify_attestation(att, revoked)
    _dump(result)
    return 0 if result["valid"] else 1


def cmd_revoke_attestation(args, _registry):
    rec = record_revoke(args.ledger, args.id, reason=args.reason or "", now=args.now)
    _dump({"revoked": args.id, "att_ledger_index": rec["index"],
           "record_hash": rec["record_hash"], "chain": verify_attestation_ledger(args.ledger)})
    return 0


def cmd_verify(args, _registry):
    _dump(verify_ledger(args.ledger))
    return 0


def cmd_report(args, registry):
    packet = _load_json(args.input)
    result = _evaluate(registry, args.pack, packet, args.now)
    md = render_markdown(result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
        _dump({"report": args.out, "verdict": result["verdict"]})
    else:
        print(md)
    return 0


def cmd_pack(args, registry):
    _dump({
        "packs": [
            {"name": p["name"], "version": p["version"], "predicates": p["predicates"],
             "source_project": p["source_project"], "fingerprint": p["fingerprint"][:16]}
            for p in registry["packs"].values()
        ],
        "dropped": registry["dropped"],
        "errors": registry["errors"],
    })
    return 0


def cmd_audit(args, registry):
    ledger = args.ledger or os.path.join(args.dir, "audit-ledger.jsonl")
    report = run_audit(args.dir, registry, ledger, now=args.now,
                       attest_out=args.attest_out, pack_override=args.pack,
                       att_ledger=args.att_ledger)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(render_audit_markdown(report))
    _dump(report)
    if not report["chain"]["valid"] or report["unroutable"]:
        return 2  # operational failure
    return 1 if report["by_verdict"]["breach"] > 0 else 0  # policy failure vs all-clear


def cmd_determinism(_args, _registry):
    report = check_tree(ROOT)
    _dump(report)
    return 0 if report["clean"] else 1


def render_markdown(result):
    lines = [
        f"# Attestra Report — {result.get('subject', '')} ({result.get('pack', '')})",
        "",
        f"- verdict: **{result['verdict']}**",
        f"- worst: {result.get('worst')}",
        f"- source_project: {result.get('source_project', '')}",
        "",
        "## Checks",
        "",
        "| gate | verdict | evidence_path | reason |",
        "|---|---|---|---|",
    ]
    for c in result.get("checks", []):
        lines.append(f"| {c['gate']} | {c['verdict']} | `{c.get('evidence_path','')}` | {c['reason']} |")
    lines.append("")
    return "\n".join(lines)


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--now", default="", help="injected timestamp metadata (default empty)")

    p = argparse.ArgumentParser(prog="attestra", parents=[common],
                                description="Deterministic verdict/attestation platform")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sample", parents=[common], help="write a pack's sample packets")
    s.add_argument("--pack", required=True)
    s.add_argument("--out", default="examples")

    s = sub.add_parser("run", parents=[common], help="evaluate a packet (single pack or --pipeline)")
    s.add_argument("--pack")
    s.add_argument("--pipeline", help="comma-separated pack names")
    s.add_argument("--input", required=True)
    s.add_argument("--ledger")

    s = sub.add_parser("attest", parents=[common], help="issue an attestation for a non-breach verdict")
    s.add_argument("--pack", required=True)
    s.add_argument("--input", required=True)
    s.add_argument("--att-ledger", dest="att_ledger", help="record the issue event to this attestation ledger")

    s = sub.add_parser("verify-attestation", parents=[common],
                       help="verify an issued attestation binds its body and is not revoked")
    s.add_argument("--input", required=True)
    s.add_argument("--ledger", help="attestation ledger to check for revocation")

    s = sub.add_parser("revoke-attestation", parents=[common],
                       help="append a revoke event for an attestation id")
    s.add_argument("--id", required=True)
    s.add_argument("--ledger", required=True)
    s.add_argument("--reason", help="revocation reason")

    s = sub.add_parser("verify", parents=[common], help="verify a ledger's hash chain")
    s.add_argument("--ledger", required=True)

    s = sub.add_parser("report", parents=[common], help="render a markdown verdict report")
    s.add_argument("--pack", required=True)
    s.add_argument("--input", required=True)
    s.add_argument("--out")

    sub.add_parser("pack", parents=[common], help="list loaded packs").add_argument(
        "list", nargs="?", help="(positional, optional)")

    s = sub.add_parser("audit", parents=[common],
                       help="batch-evaluate a directory of packets into one audit ledger")
    s.add_argument("--dir", required=True)
    s.add_argument("--ledger", help="audit ledger path (default <dir>/audit-ledger.jsonl)")
    s.add_argument("--attest-out", dest="attest_out", help="dir to write issued attestations")
    s.add_argument("--att-ledger", dest="att_ledger", help="record issue events to this attestation ledger")
    s.add_argument("--pack", help="force every packet through this pack")
    s.add_argument("--report", help="write a markdown summary to this path")

    sub.add_parser("determinism", parents=[common], help="scan kernel+packs for boundary violations")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    registry = load_packs()
    dispatch = {
        "sample": cmd_sample, "run": cmd_run, "attest": cmd_attest, "verify": cmd_verify,
        "verify-attestation": cmd_verify_attestation, "revoke-attestation": cmd_revoke_attestation,
        "report": cmd_report, "pack": cmd_pack, "audit": cmd_audit, "determinism": cmd_determinism,
    }
    if args.cmd == "run" and not args.pack and not args.pipeline:
        print("run requires --pack or --pipeline", file=sys.stderr)
        return 2
    return dispatch[args.cmd](args, registry)


if __name__ == "__main__":
    raise SystemExit(main())
