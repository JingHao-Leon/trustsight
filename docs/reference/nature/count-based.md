<!-- description: Where the count-based rules come from (thresholds over matched evidence) and what a finding means. -->

# Count-Based: Rule Nature

Mechanics live on the [Count-Based system page](../rules/count-based.md).

## Where it comes from

Some signals are not a pattern but a *rate*: how many network calls, how many
new dependencies, how many distinct hosts, how many decode steps. One is
normal, a dozen is a different animal. The count-based family watches those
magnitudes and flags the recipe that crosses a learned threshold, without
claiming any single occurrence was wrong.

These rules trade precision for reach: a kitchen-sink build can trip them
benignly, so their thresholds are set from the benign corpus's actual
distribution rather than from intuition.

## What a finding means

- The finding reports the count and the threshold, so the reviewer can judge
  whether the volume is explained by the package's purpose.
- These are context rules: read alongside the concrete findings they magnify,
  not as standalone accusations.
- Because traffic and dependency counts drift with ecosystem fashion, their
  thresholds are the ones most likely to be retuned; treat a persistent
  benign count finding as a calibration note.

## See also

- [Corpus and Priors](../../explanation/corpus-and-priors.md)
- [Fire Rates](../../explanation/fire-rates.md)
- [Count-Based system page](../rules/count-based.md)
