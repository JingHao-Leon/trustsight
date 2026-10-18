<!-- description: Where the indicator rules come from (concrete observable markers) and what a finding means. -->

# Indicators: Rule Nature

Mechanics live on the [Indicators system page](../rules/indicator.md).

## Where it comes from

Where the behavioural families reason about *shape*, the indicator family
matches *specific observables*: a known-bad host, a known campaign's literal,
a specific metadata endpoint. These are the atomic facts that the collective
correlation rules (G-series) aggregate, and the ones a maintainer can
override when a stated use is legitimate.

Indicators age. A host that was malicious last year may be a recycled CDN
today, so indicator findings carry provenance and date, and the
override-tolerance logic exists to let a known-good explanation suppress one
without suppressing the class.

## What a finding means

- The finding is a concrete match, with the matched observable and its
  provenance (which corpus or campaign it came from).
- An indicator match is strong evidence of the *specific* past activity; it
  is not proof the current diff is malicious, because observables are reused.
- An indicator suppression must be terminal-visible: when a reviewer
  overrides one, the report still shows what was suppressed and why, so a
  stale override cannot hide a re-appearance.

## See also

- [Override Tolerance](../../explanation/override-tolerance.md)
- [Indicators system page](../rules/indicator.md)
