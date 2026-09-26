# SOC-in-a-Repo — detection lab with LLM triage

A vendor-neutral **detection-engineering** pipeline that publishes two numbers
most portfolios never separate — **coverage attempted** vs **coverage
validated** — and an **LLM-assisted alert-triage** layer that is *scored against
manual labels* instead of merely looking plausible.

The entire compile → validate → coverage → triage → evaluate loop runs
**offline, deterministically, in seconds** — no API key, no network, no Docker.
The same compiled detections deploy to a real Wazuh + Sysmon stack via the
infrastructure-as-code in [`infra/`](infra/).

```bash
pip install -e .
socrepo demo            # full pipeline, offline, < 10 minutes (really ~1s)
```

## Why this exists

Two failure modes are endemic to detection portfolios:

1. **Coverage theatre.** "We cover 200 techniques" usually means "we wrote 200
   Sigma files," not "200 detections compile, deploy, and actually fire." This
   project only counts a detection as *attempted* once it **compiles** to a
   deployable Wazuh rule, and as *validated* once an atomic **makes it fire**.
   The gap between them is the most honest figure in the repo.
2. **LLM triage hand-waving.** "We added AI triage" rarely comes with a
   confusion matrix. Here, every verdict is compared to an independent analyst
   label, and a fair, context-aware **heuristic baseline** runs alongside the LLM
   so you can see exactly what the model buys.

## The two metrics

| Metric | Definition | Why it is hard to fake |
|---|---|---|
| **Coverage attempted** | An in-scope ATT&CK technique has a **compiled, deployable** detection. | The compiler refuses constructs it cannot faithfully translate and reports them; skipped rules do not count. |
| **Coverage validated** | An **atomic** actually caused that detection to fire. | Computed by running the compiled PCRE2 patterns against telemetry, not hand-asserted. `validated ≤ attempted` by construction. |
| **Validation gap** | attempted − validated | Detections you have written but cannot yet trust. |

Current published coverage (`docs/coverage_matrix.md`):

- **Techniques in scope:** 12
- **Coverage attempted:** 9/12 (75.0%)
- **Coverage validated:** 8/12 (66.7%)
- **Validation gap:** 1 (a compiled detection never proven to fire)

The scope deliberately includes techniques with **no** detection and one that is
**attempted-but-not-validated**, so the headline number is honestly below 100%.

## Triage results

Heuristic baseline on 48 manually-labelled alerts (`docs/confusion_matrix.md`):

| metric | value |
|---|---|
| accuracy | 0.771 |
| macro precision / recall / F1 | 0.766 / 0.803 / 0.775 |
| true_positive recall | 0.92 |
| true positives closed as false positive | **0** |

|  true ╲ pred | TP | benign-susp | FP |
|---|:--:|:--:|:--:|
| **true_positive** | 12 | 1 | 0 |
| **benign_suspicious** | 2 | 16 | 6 |
| **false_positive** | 0 | 2 | 9 |

The errors concentrate in the `benign_suspicious ↔ false_positive` calibration
band and in documented *context-flip* cases (e.g. a sanctioned tool downloaded
from a raw IP on a test subnet). Those are exactly the business-context calls a
rule-based baseline cannot make — the motivation for the LLM layer. Run with
`socrepo demo --provider anthropic` (key required) to compare.

## Quickstart

```bash
# 1. Install (editable) into a virtualenv
python -m venv .venv && . .venv/bin/activate
pip install -e .

# 2. Run the whole thing offline
socrepo demo
# or the shell wrapper:
./scripts/demo.sh

# 3. Or step through it
socrepo compile                     # detections/sigma/*.yml -> Wazuh rules
socrepo validate                    # simulate atomics, record which rules fire
socrepo coverage                    # publish attempted vs validated matrix
socrepo triage --provider heuristic # verdict + confidence + next action
socrepo evaluate                    # confusion matrix vs manual labels

# 4. Optional: LLM triage
export ANTHROPIC_API_KEY=sk-...
socrepo triage --provider anthropic --costs
```

Every command writes its artifact and prints where it landed. `--help` on any
command documents its flags.

## Deploy the detections (infrastructure-as-code)

```bash
cd infra
cp .env.example .env        # change every password
docker compose up -d        # single-node Wazuh indexer + manager + dashboard
socrepo compile             # regenerate config/wazuh/local_rules.xml
docker compose restart wazuh.manager
```

The manager bind-mounts the compiled rules; add the Sysmon config and the agent
channel snippet to a disposable Windows VM, run the pinned atomics, and confirm
the rules fire in the dashboard. Full instructions: [`infra/README.md`](infra/README.md).

## Repository layout

```
detections/sigma/         Sigma rules (source of truth), incl. one UNSUPPORTED
config/wazuh/             compiled local_rules.xml + ossec.conf snippets
config/sysmon/            scoped Sysmon config (process creation)
infra/                    docker-compose Wazuh+Sysmon lab (IaC)
src/socrepo/              the pipeline
  ├─ sigma_compiler.py    documented Sigma subset -> Wazuh PCRE2 (+ skip report)
  ├─ detection_engine.py  in-memory PCRE2 matcher (makes "validated" real)
  ├─ atomic_runner.py     scope loading, simulated + double-gated live atomics
  ├─ coverage.py          attempted vs validated matrix
  ├─ evaluation.py        confusion matrix (no sklearn)
  ├─ triage/              rubric, versioned prompts, providers, engine+fallback
  └─ cli.py               compile/validate/coverage/triage/evaluate/demo
data/                     attack_scope, telemetry, sample alerts + labels
docs/                     ARCHITECTURE, TRIAGE_RUBRIC, generated matrices
tests/                    48 tests, fully offline
scripts/                  demo.sh, deterministic corpus generator
```

## Design commitments

- **Attempted ≠ validated**, and the gap is surfaced everywhere.
- **The compiler refuses what it cannot faithfully translate** — no silent
  partial compiles inflating coverage.
- **Validation is computed by running detections**, not asserted.
- **The heuristic baseline is fair, not a strawman**, so the LLM has to beat
  something real.
- **The pipeline runs offline** so CI and the demo are reproducible.
- **Live atomic execution is double-gated** and Windows-only.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and
[`LIMITATIONS.md`](LIMITATIONS.md) for exactly where the model stops and the live
lab takes over.

## Development

```bash
pip install -e ".[dev]"
pytest -q            # 48 tests, offline
ruff check .
```

CI (`.github/workflows/ci.yml`) lints, runs the tests, compiles the detections,
and regenerates the coverage matrix on every push.

## License

MIT — see [LICENSE](LICENSE).
