#!/usr/bin/env bash
# Deterministic full smoke: unittest + determinism + audit loop + attestation
# ledgers + (optional) HELIX bridge. One command, injected `now`, no wall clock.
#
# Usage: scripts/smoke.sh [NOW]     (NOW default 2026-07-05)
set -euo pipefail
cd "$(dirname "$0")/.."
NOW="${1:-2026-07-05}"
TMP=".smoke_tmp"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
rm -rf "$TMP"; mkdir -p "$TMP"

echo "[1/6] unittest"
python -m unittest discover -s tests -q

echo "[2/6] determinism boundary"
python cli.py determinism >/dev/null && echo "      clean"

echo "[3/6] sample + closed audit loop"
for p in handback gen-cert reserve-flow spend-boundary; do
  python cli.py sample --pack "$p" --out "$TMP" >/dev/null
done
# audit exits 1 when a breach is present (expected: each pack ships a breach sample)
python cli.py audit --dir "$TMP" --att-ledger "$TMP/att.jsonl" \
  --attest-out "$TMP/att" --now "$NOW" >/dev/null || true
echo "      audit ran (verdict + attestation ledgers written)"

echo "[4/6] verify verdict ledger chain"
python cli.py verify --ledger "$TMP/audit-ledger.jsonl" >/dev/null && echo "      valid"

echo "[5/6] verify attestation ledger chain"
python cli.py verify --att-ledger "$TMP/att.jsonl" >/dev/null && echo "      valid"

echo "[6/6] HELIX bridge (read-only, if a HELIX root is at ..)"
if [ -d "../examples/exploit_state" ]; then
  python cli.py helix-audit --helix-root .. --ledger "$TMP/helix.jsonl" --now "$NOW" >/dev/null
  python cli.py verify --ledger "$TMP/helix.jsonl" >/dev/null && echo "      helix-audit chain valid"
else
  echo "      (skipped: no HELIX root at ..)"
fi

echo "SMOKE OK"
