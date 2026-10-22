<!-- description: How rule series, subjects, system and nature pages, evidence layers, tiers and capabilities differ - and which of them appear in a report. -->

# Rule Labels Explained

A TrustSight finding carries more than one label, and several of the names
sound like they mean the same thing. They do not. This page puts the labels
side by side, says which ones are independent, and says where each one shows
up when you read a report.

## The short version

| Label | Question it answers | Values | Where it is defined | Independent axis? |
|---|---|---|---|---|
| **Rule series** (family) | *How* does the rule reach its conclusion? | `R`, `H`, `C`, `D`, `S`, `X`, `T`, `G`, `E`, `I`, `M`, `A`, `U`, `P`, `W` | The first letter of the rule ID | Yes |
| **Subject** (`RuleCategory`) | *What kind of claim* does the rule make? | 22 slugs: `fetch-and-execution`, `integrity`, `temporal`, … | `src/trustsight/categories.py` | Yes |
| **Capability** (the `category` field in `rules.toml`) | *What capability* did this match touch? | `network_execution`, `obfuscation`, `installer`, … | Per rule in `rules.toml` | No, per match |
| **Evidence layer** | *What kind of evidence* is the finding? | `L1`-`L8` (plus the optional `L9` build lane) | Derived from the series in `src/trustsight/layers.py` | Mostly derived |
| **Evidence tier** | *How is the signal sourced* for scoring? | `A`, `B`, `C`, `D` | Scoring documentation | No, a scoring concept |

Only the first two are independent classification axes. The rest are either
derived (layer), per-match metadata (capability), or scoring vocabulary
(tier).

## Two real axes: series and subject

**Series is mechanism.** It is the leading letter of the rule ID: `R` for a
regex, `H` for a heuristic, `C` for a structural invariant, `D` for a graph
walk, `X` for an evasion check, and so on. It determines what you can tune,
where the detection code lives, and what it costs to replay. The
[Rule Series page](../reference/rules/nature.md) documents all of them.

**Subject is claim.** It is the closed `RuleCategory` set: fetch and
execution, obfuscation, integrity, temporal context, and the rest. It decides
which reference page owns the rule and how the documentation is grouped. The
[Rules Overview](../reference/rules/index.md) is the catalog by subject.

The two cross-cut. A temporal finding can come from an `H` heuristic
(`H020`) or a `T` history read (`T001`). An integrity claim can be a regex
(`R024`), a heuristic (`H001`), or a structural invariant (`C001`). Neither
axis can be computed from the other.

## System and Nature are the two halves of a subject

"System page" and "Nature page" are not labels on a rule. They are the two
documentation pages a single subject gets:

- The **system page** (`docs/reference/rules/<subject>.md`) owns the
  mechanics, fields, severities and per-rule definitions. Its generated
  "Rules on this page" table lists every rule in the subject.
- The **Nature page** (`docs/reference/nature/<subject>.md`) owns the
  interpretation: where the idea came from and what a finding means in the
  world. Its generated line at the top lists the rule IDs, so the series mix
  is visible on the page, but the definitions stay on the system page.

They are paired by subject, not by series. There is exactly one of each per
subject.

## Layer is evidence kind, derived from series

The evidence layer answers a different question: *what kind of check produced
this finding?* `L1` is structural coherence, `L3` is a payload signature, `L6`
is ecosystem memory, `L8` is campaign correlation, and so on.

The mapping is mostly a per-series default:

| Series | Default layer |
|---|---|
| `C`, `P` | `L1` |
| `W` | `L2` |
| `R`, `S`, `U` | `L3` |
| `X`, `E` | `L4` |
| `H` | `L5` |
| `D`, `T` | `L6` |
| `I` | `L7` |
| `G` | `L8` |

A small override table splits three series where the mechanism diverges from
the evidence: history-backed `H` rules move to `L6`, `H056` and `U007`/`U008`
move to `L7`, `H099`/`H101`/`H103` and `U009` move to `L1`, and `X026`/`X027`
move to the readability boundary at `L2`. `M` has no layer at all because it
fires at its inputs' layer.

Two consequences:

- **The numbers are not stages.** `L1` to `L8` is a stable display order, not
  a sequence of barriers an attacker passes. A finding is labelled by the
  check that caught it, not by every layer that might have caught it. The
  report says `L4 fired, L3 none` when an evasion rule catches what the
  payload rules missed; that is not a claim that the attacker reached `L4`.
- **The layer is a report and coverage view.** A tokenizer gap blinds `L1` to
  `L4`, a history gap blinds only `L6`, and the report can say that without
  pretending a series is unread. `L9` is the optional artifact build lane,
  outside the static `L1`-`L8` set; `L0` is the release process, not a rule.

See [Assurance Layers](../assurance-layers.md) and
[evidence categories](../assurance-layers/evidence-categories.md) for the
full model.

## Tier is about sourcing, not classification

The evidence tier (`A`-`D`) says how much external data a scoring signal
needs: `A` structural and always available, `B` static priors, `C` history
that needs a warm corpus, `D` declared verification that is reported but
never scored. It is not a field every rule is filed under; it describes the
signal's sourcing and confidence. See
[Evidence Tiers](../reference/evidence-tiers.md).

## Capability is the `category` field, not the subject

`rules.toml` has a per-rule field literally named `category`. That is a
historical name for the **capability** a match touched
(`network_execution`, `installer`, `obfuscation`). It is fine-grained, set per
rule, and used by `H027` to count capability density. It is not the subject
and does not decide which documentation page owns the rule.

## A worked example: `R001`

| Label | Value for `R001` |
|---|---|
| Series | `R` (regex) |
| Rule ID | `R001` |
| Subject | Fetch and Execution |
| Capability | `network_execution` |
| Layer | `L3` (payload signature, the `R` default) |
| Tier | `A` (structural) |

Reading the report:

- The finding line `+25 HIGH R001 …` shows the **series** (`R`) as part of the
  ID, plus the rule number and severity.
- The `layers` object shows `L3` fired and carries `R001`.
- The **subject** appears only in the documentation; it is not in the finding
  payload.
- The **tier** and **capability** are analysis and scoring vocabulary, not
  report fields.

## Where to go next

- [Rule Series](../reference/rules/nature.md); the mechanism axis in full
- [Rules Overview](../reference/rules/index.md); the subject catalog
- [Rule Nature](../reference/nature/index.md); the interpretation half of each subject
- [Assurance Layers](../assurance-layers.md); layers, coverage and verdicts
- [Reading a Report](../tutorial/reading-a-report.md); the report itself
