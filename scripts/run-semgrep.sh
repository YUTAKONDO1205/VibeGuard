#!/usr/bin/env bash
# ④ — produce Semgrep --json for the SAST baseline comparison, then diff it
# against VibeGuard with scripts/sast-baseline-eval.mjs.
#
# Semgrep has no Windows-native build (OCaml core), so run this on Linux/macOS/CI
# or via Docker. The companion harness ingests the resulting JSON unchanged, so
# the multi-language tables reproduce exactly the Bandit run's structure.
#
# Usage:
#   scripts/run-semgrep.sh <corpus-dir> <label>
# Example:
#   scripts/run-semgrep.sh samples/vulnerable "samples/vulnerable (multi-lang)"
set -euo pipefail

CORPUS="${1:-samples/vulnerable}"
LABEL="${2:-$CORPUS}"
OUT="paper_data/semgrep_$(echo "$CORPUS" | tr '/ ' '__').json"

# A fixed, public, login-free ruleset for reproducibility. p/default is the
# general security pack; swap for p/security-audit or p/owasp-top-ten as needed.
CONFIG="${SEMGREP_CONFIG:-p/default}"

if command -v semgrep >/dev/null 2>&1; then
  semgrep --config="$CONFIG" --json --metrics=off --output "$OUT" "$CORPUS" || true
else
  # Docker fallback (needs a running daemon + network to fetch the ruleset).
  docker run --rm -v "$(pwd):/src" semgrep/semgrep \
    semgrep --config="$CONFIG" --json --metrics=off --output "/src/$OUT" "/src/$CORPUS" || true
fi

# Produce the VibeGuard side and run the comparison.
node apps/cli/dist/index.js "$CORPUS" --format json --fail-on never > paper_data/vg_semgrep_corpus.json
node scripts/sast-baseline-eval.mjs "$LABEL" paper_data/vg_semgrep_corpus.json "$OUT"
