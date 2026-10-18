<!-- description: Where the temporal rules come from (timing and sequencing as evidence) and what a finding means. -->

# Temporal Context: Rule Nature

Mechanics live on the [Temporal Context system page](../rules/temporal.md).

## Where it comes from

Some attacks are only visible in time. A commit made at 03:00, a burst of
publications inside one minute, a change reverted and reapplied, an update
that lands days after the maintainer went quiet: none of these is anomalous
on its own line, but the *when* is data a single-snapshot review throws away.

The rules compare the current run against a baseline in the observation
store, so they need history to say anything. On a cold store they stay quiet
by construction rather than guessing.

## What a finding means

- The finding compares this run to what came before: a change of behaviour,
  a burst, a near-simultaneous edit to many packages.
- Temporal findings are contextual and weak in isolation; they matter as
  corroboration for a code change that already looked odd.
- An empty history is not a clean bill of health. It means the temporal rules
  cannot see yet, which the run reports as reduced coverage.

## See also

- [Cold Start and Maturity](../../explanation/cold-start-and-maturity.md)
- [Corpus and Priors](../../explanation/corpus-and-priors.md)
- [Temporal Context system page](../rules/temporal.md)
