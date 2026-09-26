# Architecture

SOC-in-a-Repo is a detection-engineering pipeline that produces two honest
numbers — **coverage attempted** and **coverage validated** — and an LLM/heuristic
triage layer scored against manual labels. This document explains how the pieces
fit and, more importantly, *why the design refuses to inflate its own metrics*.

## Design principles

1. **Attempted ≠ validated.** Writing a Sigma rule is not detection coverage.
   A rule counts as *attempted* only once it **compiles** to a deployable Wazuh
   rule, and as *validated* only once an atomic actually makes that rule fire.
   The gap between the two is surfaced everywhere.
2. **The compiler refuses what it cannot faithfully translate.** A silent
   partial compile is how coverage numbers get inflated. Our compiler emits a
   report of skipped rules and they simply do not count.
3. **Validation is computed, not asserted.** `validated` comes from running the
   compiled PCRE2 field patterns against telemetry, not from a hand-maintained
   list.
4. **The baseline is fair.** The heuristic triage provider is context-aware, so
   the LLM has to beat a real baseline, not a strawman.
5. **The pipeline runs offline.** No API key, no network, no Docker are required
   for the full compile → validate → coverage → triage → evaluate loop, which is
   what makes CI and the demo reproducible.

## Component map

```
detections/sigma/*.yml
        │  sigma_compiler.py  (documented subset → PCRE2, skip-report)
        ▼
config/wazuh/local_rules.xml ─────────────────────────► deployed to Wazuh (infra/)
        │
        │  detection_engine.py  (in-memory PCRE2 matcher)
        ▼
data/validation/atomic_telemetry.jsonl ──► validation results (which rules fired)
        │
        │  coverage.py
        ▼
docs/coverage_matrix.md/.json   (attempted vs validated vs gap)

data/sample_alerts/alerts.jsonl
        │  triage/ (engine + providers + rubric + prompts)
        ▼
data/triage_results.jsonl   (verdict + confidence + next action, cost/latency)
        │  evaluation.py     vs  data/labels/manual_labels.csv
        ▼
docs/confusion_matrix.md    (agreement, per-class P/R/F1, error cells)
```

## Modules

| Module | Responsibility |
|---|---|
| `sigma_compiler.py` | Translate a *documented subset* of Sigma into Wazuh PCRE2 rules; report every skipped construct via `CompileReport`. |
| `detection_engine.py` | Apply compiled field patterns to process-creation events in memory (AND across fields, case-insensitive PCRE2). This is what makes `validated` real. |
| `atomic_runner.py` | Load the ATT&CK scope, replay pinned telemetry for simulated validation, and — double-gated — run live atomics on Windows. |
| `coverage.py` | Build and render the ATT&CK coverage matrix and the two headline metrics. |
| `triage/rubric.py` | The shared verdict rubric and the JSON output contract; parse/validate provider output. |
| `triage/prompts.py` | Versioned system/user prompts (prompt version is recorded). |
| `triage/providers.py` | `HeuristicProvider` (deterministic baseline + fallback) and `AnthropicProvider` (optional LLM). |
| `triage/engine.py` | Orchestration: primary provider with guaranteed per-alert fallback, plus cost/latency telemetry. |
| `evaluation.py` | Confusion matrix and per-class metrics, computed from scratch (no sklearn) for auditability. |
| `cli.py` | `compile` / `validate` / `coverage` / `triage` / `evaluate` / `demo`. |

## The Sigma subset

The compiler supports the constructs this rule set needs and **refuses the
rest** rather than mis-translating them:

* field modifiers `endswith` / `startswith` / `contains` / `all`
* value lists (OR) and `|all` (AND)
* conditions: a single selection, a single-key selection, `all of sel*`,
  `all of them`

Unsupported constructs (e.g. `1 of selection_*`, regex modifiers, timeframes)
are skipped and reported. `detections/sigma/proc_creation_win_powershell_encoded_UNSUPPORTED.yml`
is committed on purpose: it exercises the skip path so the honest-reporting
behaviour is visible and tested.

## Data flow for the two metrics

* **Attempted** = number of in-scope techniques (`data/mappings/attack_scope.yaml`)
  that a *compiled* rule maps to via its `attack.tXXXX` tags.
* **Validated** = in-scope techniques that both have a compiled rule **and** had
  an atomic make a rule fire.

Because `validated` requires `has_detection`, it can never exceed `attempted`,
so `validation_gap = attempted − validated ≥ 0` by construction.

## Triage layer

Every alert flows through `TriageEngine.triage_one`, which returns
`(result, fell_back)`:

* if the primary provider is available and succeeds → its result, `fell_back=False`;
* if the primary is unavailable or raises → the heuristic result, `fell_back=True`.

This guarantees the pipeline always completes and that any degradation is
*auditable* (counted in the run telemetry and flagged per alert) rather than
silent — the v0.3 "fallback when the LLM is unavailable" requirement.

Both providers are judged against the **same rubric** and the **same manual
labels**, so the confusion matrix shows exactly what the LLM buys over the free,
deterministic baseline.

## Reproducibility

Reproducibility is a first-class requirement, not a nice-to-have:

* **Atomic GUID pinning.** Every technique in `data/mappings/attack_scope.yaml`
  lists explicit Atomic Red Team `guid`s. Validation telemetry is keyed by the
  same `auto_guid`, so "validated" always refers to a *specific, pinned* atomic,
  not "whatever the latest Atomics repo happens to contain." When you bump the
  Atomics version, you update the GUIDs deliberately and the change is diffable.
* **Committed sample corpus generator.** `scripts/build_sample_corpus.py`
  regenerates `data/sample_alerts/alerts.jsonl` and `data/labels/manual_labels.csv`
  deterministically, with provenance documented in the script. The labels are an
  independent analyst judgement, *not* reverse-engineered from the heuristic
  scorer — which is what makes the confusion matrix meaningful.
* **Offline determinism.** The heuristic provider is pure and stateless, so the
  demo and CI produce identical numbers on every run.
* **Pinned infrastructure.** `infra/docker-compose.yml` pins image tags.

## What is modelled vs real

The in-memory `detection_engine` is a faithful-enough model of Wazuh's
process-creation field matching (AND across `<field>` tags, case-insensitive
PCRE2) so that `validated` can be computed in CI without a live endpoint. The
**same compiled rules** are what deploy to the real Wazuh manager in `infra/`,
so the modelled validation and the live lab agree by construction. See
[LIMITATIONS.md](../LIMITATIONS.md) for exactly where the model stops.
