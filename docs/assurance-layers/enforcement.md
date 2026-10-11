<!-- description: Tests and adversarial evaluation: what the gates prove about the layer model's implementation, and what the harness measures about detection diversity. -->

# Part 4: Tests and adversarial evaluation

This page answers: what do the automated tests actually establish?

Three different claims are often confused. This page keeps them apart:

| Claim | What substantiates it | Status |
|---|---|---|
| The layer model is **implemented correctly** | The security gates in `scripts/security_gates.py` | Gated in CI |
| The mechanisms give **complementary coverage** | The adversarial harness (`trustsight-harness`) | Measured; results not yet published here |
| The tool **performs well on real threats** | Independent, ideally blinded evaluation | External, not claimed |

Passing the gates establishes only the first. A gate that passes is not
evidence that a malicious package will be detected.

## Implementation gates

The layer model's invariants are enforced by gates that fail the build:

| Gate | Invariant |
|------|-----------|
| `every rule carries exactly one layer` | Every categorised rule maps to exactly one evidence category; M and A have none by design. |
| `layer detection and coverage are independent` | A fired category and an incomplete category are reported as separate facts. |
| `every rule names its shared dependencies` | Every rule has a mechanism, subject, evidence source and shared-dependency entry. |
| `docs layer mapping matches the registry` | The Part 1 table is generated from `trustsight.layers`; prose cannot drift from code. |
| `layer overrides stay within the closed set` | A `[layers]` config override cannot move a rule outside L1-L8. |
| `boundaries are the coverage view` | Every coverage gap maps to a boundary; the two representations cannot diverge. |

Run them whole with:

```bash
python scripts/security_gates.py
```

The `every rule names its shared dependencies` gate reads
`trustsight.detectors`, which records each family's mechanism, evidence source
and shared infrastructure (tokenizer, history database, corpus, ...). This is
what makes common-mode failure visible: two different mechanisms that share a
dependency can go blind together.

## Adversarial evaluation (the harness)

The **adversarial harness** (`trustsight-harness`) attacks the tool and records
which evidence categories fire on each attempt. For each attempt it records
`observed_layers` - the categories that actually fired - and rolls the
campaign up into:

- **minimum layer-cut**: the exact smallest set of fired categories that covers
  every caught attempt (enumerated, not approximated; `exact_minimum_cut` is
  the same function under its explicit name). A fully-bypassed attempt
  (nothing fired) is uncuttable and is reported separately as a bypass
  (`layers_fully_bypassed` is the count).
- **single-layer-failure**: for each category, how many caught attempts fire
  *only* in that category - disable it and they pass. This is the empirical
  "does one layer's failure reopen a path" number.
- **resilience distribution**: the histogram of how many distinct categories
  caught each caught attempt. A campaign whose mass sits at `1` is one
  regression from a bypass regardless of its minimum cut.
- **bypasses**: attempts that fired nothing (`fully_bypassed`).

An earlier version of this metric inferred a traversal path, which made every
path contain L1 and the minimum cut structurally one. It is now a projection
of the categories that fired, and the cut is exact.

The harness's own gates are unchanged: it never executes package code (a
`bash -n` syntax check at most), and its records are telemetry only.

## What is published, and what is not

The harness's CLI now prints a `layer_resilience` summary for every campaign:
attempts, outcome counts, bypasses, the exact minimum layer-cut, the
single-layer-failure counts, the resilience distribution, and the campaign's
declared attack-set **limitations** (`limitations` in the record). Those
numbers are per campaign and depend on the attack set; the limitations travel
beside them so a rate is never read as a whole-corpus claim.

What is **not** on this page is a single rolled-up figure across every
campaign. A cross-campaign published number would have to state its combined
attack-set limitations; until that exists, treat the "complementary coverage"
claim as a hypothesis the harness is built to test, not an established
property - and note the third level, real-world performance, is external
evaluation this project does not claim.

## See Also

- [Part 3: Reporting](reporting.md)
- [The security enforcement map](../security/enforcement-map.md) - the
  threat-model gates this section complements
- [Fire rates](../explanation/fire-rates.md) - the calibration gates
