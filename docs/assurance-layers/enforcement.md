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
  every caught attempt (enumerated, not approximated). A fully-bypassed attempt
  (nothing fired) is uncuttable and is reported separately as a bypass.
- **single-layer-failure**: for each category, how many caught attempts fire
  *only* in that category - disable it and they pass. This is the empirical
  "does one layer's failure reopen a path" number.
- **bypasses**: attempts that fired nothing.

An earlier version of this metric inferred a traversal path, which made every
path contain L1 and the minimum cut structurally one. It is now a projection
of the categories that fired, and the cut is exact.

The harness's own gates are unchanged: it never executes package code (a
`bash -n` syntax check at most), and its records are telemetry only.

## What is not yet published

The review that prompted this rewrite asked, fairly, for the harness results
themselves: attack counts by class, bypass rates, the minimum-cut
distribution, and the limitations of the attack set. Those numbers are
recorded per campaign but are **not yet summarised on this page**. Until they
are, treat the "complementary coverage" claim as a hypothesis the harness is
built to test, not an established property.

## See Also

- [Part 3: Reporting](reporting.md)
- [The security enforcement map](../security/enforcement-map.md) - the
  threat-model gates this section complements
- [Fire rates](../explanation/fire-rates.md) - the calibration gates
