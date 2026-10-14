<!-- description: Why TrustSight caps how many findings a terminal shows, and why the cap is always reported rather than silent. -->

# Alert Budget

A tool that reports everything a noisy package does can be turned against the
person reading it. Fill the screen with findings and the real one scrolls
past.

The alert budget is the guard against that. It caps how much the **terminal**
shows at once, and it always says when it did.

## Where it comes from

The analogy is a **superantigen**. A normal immune response is targeted. A
superantigen instead activates a huge fraction of T cells at once, and the
resulting flood of signals does more damage than the pathogen - the response
becomes the threat, and the host stops reacting to anything real.

The same thing happens to a reviewer. A campaign that makes every package
moderately noisy is not attacking any single package; it is **raising the
noise floor** until reviews get skimmed. That is the attack the budget
exists to blunt.

## What the cap does

- **`[alerts] max_rendered_findings`** (default 50). The terminal shows the
  first 50 findings in full, then a single `...and N more findings (see
  --json)` line.
- The JSON report is **never filtered**. Every finding is there. The cap only
  bounds what a person reads on screen.
- A weight-0 boundary, **W010 (Alert Volume Capped)**, records that the cap
  was reached, with the count per severity band.

## It is a saturation, not a gap

This is the important distinction. A coverage gap (the [W-series
rules](../reference/rules/unverifiable.md)) means *something was not read* -
the analysis could not conclude, and that is a boundary that forbids a clean
verdict.

W010 is the opposite. Nothing was left unread; the report simply had more to
say than fits comfortably on screen. So W010 never forbids a clean verdict
and never changes the score. It is a statement about the **run**, not about
the package.

## The same idea, one level up

A single `full-aur --watch` cycle can flag hundreds of packages at once. The
per-cycle cap (`[alerts] max_cycle_alerts`) keeps one noisy cycle from
becoming one enormous notification: past the cap the webhook names the top-K
by score and reports the counts, while the stored record keeps every package.

Volume is never evidence about any single package, so none of this ever moves
a score.

## Related

- [Campaign Alert Mode](campaign-alert-mode.md) - the other guard, against a
  state that never expires.
- [Kinds of Alerts](kinds-of-alerts.md) - where W010 sits among everything
  else.
