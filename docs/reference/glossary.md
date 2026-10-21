<!-- description: The TrustSight vocabulary: rule family, subject, evidence category, evidence tier, detection, coverage, boundary, and the report terms built on them. -->

# Glossary

One page for the labels TrustSight uses, each defined once and linked to the
page that explains it in full. Four axes are easy to confuse: a rule carries a
**family** (how it works), a **subject** (what it looks for), an **evidence
category** (what kind of evidence its finding is), and an **evidence tier**
(what the signal is worth).

## How a rule is classified

**Finding.** One rule's report that it matched, with the file, side and line it
matched. A run produces a list of findings; the report groups and reads them.

**Benign false positive.** A rule hit on a genuine bad practice by the packager, where the package itself is not malicious. The finding is real; the practice is undesirable, and the fix belongs with the packager or in a documented known false positive. See [Standards](../standards.md#false-positive-vocabulary).

**Malicious false positive.** A bad rule trigger: the rule fired with no bad practice or malicious behaviour behind it. A misread option, an allowlist gap, or a counting or grouping error is a malicious false positive; the fix belongs in the detection shape and ships with the true-positive twin. See [Standards](../standards.md#false-positive-vocabulary).

**Rule family (series).** How a rule reaches its conclusion: a regex match
(`R`), a structural invariant over parsed documents (`C`), a graph walk (`D`),
a heuristic (`H`), an evasion or refusal check (`X`), a statistic (`E`), a
history read (`T`), a cross-package correlation (`G`), an indicator lookup
(`I`), a predicate over other findings (`M`), or an artifact inspection (`A`).
`P` reports declared practices and `W` reports analysis boundaries; neither is a
detection. Full list: [Rule Nature](rules/nature.md).

**Subject (category).** What a rule looks for, as a closed set with one
reference page each (fetch and execution, obfuscation, integrity, and so on). A
rule belongs to exactly one subject. Full list: [Rules Overview](rules/index.md).

**Evidence category (layer).** The kind of evidence a finding represents, one
of `L1`-`L8`
([Part 1: Evidence Categories](../assurance-layers/evidence-categories.md)). A
finding is labelled by the check that produced it, not by every other check it
might complement.

**Evidence tier.** How much external data a signal needs before it means
anything: `A` (structural, always available), `B` (priors, static lists), `C`
(history, needs a warm corpus), `D` (declared verification, reported never
weighted). Tiers are orthogonal to layers: a finding has both a tier (how it is
sourced) and a layer (what kind of evidence it is). See
[Evidence Tiers](evidence-tiers.md) and
[Scoring Philosophy](../explanation/scoring-philosophy.md).

**Shared dependencies.** The infrastructure a rule relies on: the tokenizer,
parser, history database, corpus, or indicator baseline. Two rules with
different families can share one dependency, so a single input-handling failure
can blind both. Recorded in
[`trustsight.detectors`](../assurance-layers/enforcement.md).

## How a run is reported

**Detection.** Whether a finding in a category was produced: `fired` or `none`.

**Coverage.** Whether a category could be assessed at all: `complete`,
`incomplete` (a truncated diff, an unresolvable value, a partial file), or
`not_applicable` (the analysis mode cannot exercise it, as `L8` in a
single-package review). Detection and coverage are independent: a category can
fire *and* be incompletely read. See
[Part 3: Reporting](../assurance-layers/reporting.md).

**Boundary.** One object per shortfall that forbids a clean verdict, carrying
`forbids_clean`. A boundary is the same shortfall as an `incomplete` coverage,
seen from the verdict's side. See
[the security model](../security/what-a-result-claims.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

**Verdict.** The findings rendered into a review direction, naming the fired
evidence categories. It describes what fired; it never grants permission to skip
review.

**Score and risk band.** A deterministic weight summary of the fired findings,
available on request (`--score`), never volunteered, and never a probability of
safety. See [How TrustSight Works](../explanation/index.md).

## See Also

- [Assurance Layers](../assurance-layers.md) - the `L1`-`L8` model in full
- [Rules Overview](rules/index.md) - subjects and the rule catalog
- [Evidence Tiers](evidence-tiers.md) - the `A`-`D` taxonomy
- [Security Model](../security.md) - what a result does and does not claim
