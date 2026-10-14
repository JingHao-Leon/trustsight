<!-- description: Why a TrustSight suppression can expire, and why an indicator match can make one visible again. -->

# Override Tolerance

Suppressing a finding is a deliberate act: an operator says "I know about
this, stop telling me". It is a good feature. It is also, left alone, a
permanent one - and permanence is the problem.

This page explains the two things TrustSight does to keep a suppression from
becoming a place to hide.

## Where it comes from

The immune system has the same problem and the same answer. **Peripheral
tolerance** is how the body stops attacking its own tissue: self-reactive
cells are anergized. Crucially, that tolerance is not a one-time switch. It
is maintained by *continuous* self-signal. Take the signal away and tolerance
lapses.

The attack version is **socially induced tolerance**: a mimic that keeps
presenting the tolerizing signal stays invisible forever. A suppression
written once, that never has to justify itself again, is exactly that.

## Expiring a suppression

An override can carry an optional lifetime, in **observations** - recorded
analyses, not days:

```json
{ "rule_id": "H029", "package": "some-package", "reason": "...",
  "ttl_observations": 50 }
```

Once that many observations have passed since the override was written, it
**stops suppressing**. Two things happen:

- The finding comes back at full severity.
- The report names the expiry, so a quiet report can never mean both "no
  finding" and "a suppression quietly lapsed".

Expiry never touches a FATAL finding - those cannot be suppressed in the
first place.

## The indicator cross-check

Some overrides are only meant to hold while the package looks clean. Marking
one `requires_clear_indicators` makes it conditional:

```json
{ "rule_id": "C005", "package": "some-package", "reason": "...",
  "requires_clear_indicators": true }
```

If an active indicator matches the run, the override is downgraded to
**visible-only**: the finding renders in the terminal with both the override
and the corroboration noted, instead of being hidden. A suppression must
never hide a signal the run itself found.

## Why observations, not seconds

The lifetime is counted in recorded analyses, so the tool never consults a
clock it does not control and an expired override cannot be kept alive by a
skewed system time. It is the same discipline as the freshness marker and
campaign TTLs.

## Related

- [Campaign Alert Mode](campaign-alert-mode.md) - the same expiry discipline
  applied to armed state.
- [Kinds of Alerts](kinds-of-alerts.md)
