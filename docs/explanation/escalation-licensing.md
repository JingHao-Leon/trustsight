<!-- description: How one finding can raise another's severity in TrustSight - and why that only ever amplifies, never authorizes. -->

# Escalation Licensing

A single weak signal is weak. A weak signal next to a confirming one is a
story. **Escalation licensing** lets a rule say "raise me a notch *if* one of
these other rules also fired" - and nothing more.

## Where it comes from

Borrowed from **T-cell help**. A B cell that has bound an antigen still needs
a licensed signal from a helper T cell before it commits to a full response.
Help focuses and amplifies the response. It does not create it: the B cell
already bound the antigen, and natural killer cells still destroy cells that
never presented one.

The autoimmune reading is the failure mode: treating *help* as
*authorization*. A signal that only says "this is real" must never be what
makes a finding fire in the first place.

## The one rule

A licensor only ever moves a finding **up one notch**:

```
LOW → MEDIUM → HIGH → CRITICAL
```

Never to FATAL. Never more than one notch, even if several licensors fire.
And if no licensor fires, the finding simply stands at its own severity - the
bump is lost, the finding is not. Evading the licensor can cost you the
escalation; it can never make the detection disappear.

The escalation is transparent: an escalated finding records which rules
licensed it.

## Star, not chain

Licensing is a star, not a ladder. A rule that is itself raised by another
rule cannot in turn raise a third. That keeps a single weak signal from
cascading an entire run upward through a chain of "and therefore".

## Missing help is also a signal

The mirror image matters too. If a finding fired whose rule *expects* a
licensor and none came, that is not evidence about the package - it is a
**tool-health** observation: a detector that usually travels with a partner
travelled alone. It is reported to the calibration output (like the other
M-series tool-health entries), weight 0, and never scored.

That is the design law in one line: **licensing amplifies, never authorizes;
help is a signal, and missing help is also a signal.**
