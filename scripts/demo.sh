#!/usr/bin/env bash
# --------------------------------------------------------------------------- #
# End-to-end demo — runs the whole pipeline OFFLINE in well under 10 minutes
# (typically a few seconds). No API key, no network, no Docker required.
#
#   ./scripts/demo.sh              # heuristic provider (default, deterministic)
#   ./scripts/demo.sh anthropic    # LLM provider if ANTHROPIC_API_KEY is set,
#                                   # transparently falling back to heuristic
#
# This is the "does it actually work" button. It exercises: Sigma->Wazuh
# compilation, simulated atomic validation, the coverage matrix, LLM/heuristic
# triage with a cost/latency table, and the confusion matrix against manual
# labels — then prints where every artifact landed.
# --------------------------------------------------------------------------- #
set -euo pipefail

PROVIDER="${1:-heuristic}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Prefer an installed console script; fall back to module invocation from src.
if command -v socrepo >/dev/null 2>&1; then
  SOC=(socrepo)
else
  export PYTHONPATH="${PYTHONPATH:-}:$ROOT/src"
  SOC=(python -m socrepo.cli)
fi

echo "==> SOC-in-a-Repo demo (provider: $PROVIDER)"
echo "==> repo: $ROOT"
echo

START=$(date +%s)
"${SOC[@]}" demo --provider "$PROVIDER"
END=$(date +%s)

echo
echo "==> completed in $((END - START))s"
echo "==> artifacts:"
echo "      config/wazuh/local_rules.xml   (compiled detections)"
echo "      data/validation/results.jsonl  (atomic validation)"
echo "      docs/coverage_matrix.md/.json  (attempted vs validated)"
echo "      data/triage_results.jsonl      (per-alert verdicts)"
echo "      docs/confusion_matrix.md       (agreement vs manual labels)"
