# Triage rubric

Every alert is triaged into exactly one verdict, with a calibrated confidence, a
single next action, and a short evidence-based rationale. The rubric below is the
**shared contract**: it is embedded verbatim in the LLM system prompt *and* used
as the definition the heuristic provider encodes, so both providers are judged
against the same standard and against the same manual labels.

Prompt version: `triage-2024.1` (recorded on every LLM result).

## Verdicts

| Verdict | Meaning |
|---|---|
| `true_positive` | Malicious or unauthorised activity consistent with the mapped ATT&CK technique. The alert did its job. |
| `false_positive` | Benign activity the rule should not have flagged. The detection logic — not the analyst — is at fault. |
| `benign_suspicious` | Real, unusual, or policy-violating activity that is not (yet) provably malicious. Needs a human or more context. **When genuinely unsure between TP and FP, choose this.** |

The middle class exists on purpose. Forcing every alert into TP/FP manufactures
false confidence; `benign_suspicious` is where honest uncertainty lives, and the
confusion matrix treats it as a first-class label.

## Confidence

A float in `[0, 1]`, calibrated honestly:

| Range | Interpretation |
|---|---|
| 0.9 – 1.0 | Unambiguous |
| 0.6 – 0.8 | Likely |
| 0.4 – 0.6 | Genuinely unsure |

## Next action

Exactly one, and it must be consistent with the verdict:

| Action | When |
|---|---|
| `close` | `false_positive`; the rule needs no change right now |
| `monitor` | `benign_suspicious`, low urgency; keep an eye on it |
| `hunt` | `benign_suspicious` with pivot potential; expand the search |
| `escalate` | `true_positive`; hand to incident response |
| `isolate_host` | `true_positive` with active/destructive behaviour; contain now |

## Signals to weigh

* LOLBIN invoked with attacker-style flags
* network egress to raw IP literals vs internal/reputable hosts
* parent/child anomalies (e.g. an Office app spawning a shell)
* credential-access targets (lsass)
* whether the binary is signed and in a system path
* whether the user is an administrator doing plausible admin work
* encoded / obfuscated command lines

## Output contract

Providers must return a JSON object matching this shape (the parser tolerates
code fences and surrounding prose, and clamps confidence into `[0,1]`):

```json
{
  "verdict": "one of: true_positive | false_positive | benign_suspicious",
  "confidence": "float between 0 and 1",
  "next_action": "one of: close | monitor | hunt | escalate | isolate_host",
  "rationale": "<= 2 sentences, concrete, referencing the evidence",
  "key_indicators": ["short strings naming the signals you used"]
}
```

## How the two providers apply the rubric

**Heuristic (`heuristic-v2`).** Deterministic, offline, zero-cost. It starts at a
neutral score of 0.50 and applies weighted, context-aware bumps — credential
access against lsass, downloads keyed by *destination* (raw public IP vs
internal), remote vs local WMI exec, squiblydoo, mshta fetching remote payloads,
certutil decoding **to an executable**, scheduled-task creation to user-writable
paths, encoded commands — offset by de-escalating context (SYSTEM maintenance,
read-only management sub-commands, routine single discovery commands, internal
destinations). Thresholds: `≥ 0.70 → true_positive`, `≤ 0.35 → false_positive`,
otherwise `benign_suspicious`.

This is a *fair baseline*, not a strawman: it already includes the enrichment a
detection engineer adds first. What it cannot do is reason about business context
— that a `whoami /all` spawned by Outlook right after an email open is a phishing
follow-on, or that a raw-IP download of a named security tool on a test subnet is
sanctioned. Those context-flip cases are exactly where the LLM layer earns its
cost, and they appear as the residual errors in the confusion matrix.

**Anthropic (optional).** Sends the versioned prompt to a hosted model, parses
the structured response into the same `TriageResult`, and records latency and an
approximate (configurable) cost. Any failure raises so the engine falls back to
the heuristic, per alert, with `fell_back=True`.

## Why this is the rigor step

Producing plausible verdicts is easy. The value is in `socrepo evaluate`, which
compares verdicts to independent manual labels and prints a confusion matrix with
per-class precision/recall/F1 — turning "the model sounds reasonable" into "the
model agrees with a human on N labelled alerts, and here is exactly where it does
not." See [confusion_matrix.md](confusion_matrix.md) for the current baseline.
