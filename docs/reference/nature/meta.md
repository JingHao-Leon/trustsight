<!-- description: Where the meta rules come from (the run's own health) and what an M finding means. -->

# Meta and Confluence: Rule Nature

Mechanics live on the [Meta system page](../rules/meta.md).

## Where it comes from

Every other rule is a claim about the *package*. The meta family is a claim
about the *run*: too many alerts for one window, a matcher that fired
suspiciously often, a campaign class re-arming again and again. These are
tool-health observations, and they exist so the analysis can admit when it
is not itself trustworthy.

The name "confluence" is the other half: M003 reports when independent
families agree on the same package, which is a statement about agreement
rather than about any one rule. Both halves answer "how much should this run's
own output be trusted?".

## What a finding means

- An M finding is about TrustSight, not the package under review. It never
  scores against the package and is excluded from the package's risk band.
- `M001` (volume), `M002` (a noisy matcher), and `M004` to `M006`
  (cycle/campaign health) are alerts to the operator to retune or
  investigate filters.
- `M003` (confluence) is the exception that reads a package: several distinct
  families agreeing is a real signal, and it is scored as such.
- `M006` specifically flags a campaign re-armed too often: the state is still
  refreshed, but the churn is reported so a chronic campaign does not inflate
  the alert stream.

## See also

- [Kinds of Alerts](../../explanation/kinds-of-alerts.md); operator-facing
  versus package-facing findings
- [Alert Budget](../../explanation/alert-budget.md)
- [Meta system page](../rules/meta.md)
