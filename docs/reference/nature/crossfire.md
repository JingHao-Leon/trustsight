<!-- description: Where the crossfire rules come from (military interlocking fire against evasion) and what a finding means. -->

# Crossfire

Mechanics live on the [Crossfire system page](../rules/crossfire.md).

<!-- generated: nature-rules -->
**Rules in this nature:** [X001](../rules/crossfire.md#x001), [X002](../rules/crossfire.md#x002), [X003](../rules/crossfire.md#x003), [X004](../rules/crossfire.md#x004), [X005](../rules/crossfire.md#x005), [X006](../rules/crossfire.md#x006), [X007](../rules/crossfire.md#x007), [X008](../rules/crossfire.md#x008), [X009](../rules/crossfire.md#x009), [X010](../rules/crossfire.md#x010), [X011](../rules/crossfire.md#x011), [X012](../rules/crossfire.md#x012), [X013](../rules/crossfire.md#x013), [X014](../rules/crossfire.md#x014), [X015](../rules/crossfire.md#x015), [X016](../rules/crossfire.md#x016), [X017](../rules/crossfire.md#x017), [X018](../rules/crossfire.md#x018), [X019](../rules/crossfire.md#x019), [X020](../rules/crossfire.md#x020), [X021](../rules/crossfire.md#x021), [X022](../rules/crossfire.md#x022), [X023](../rules/crossfire.md#x023), [X024](../rules/crossfire.md#x024), [X025](../rules/crossfire.md#x025), [X026](../rules/crossfire.md#x026), [X027](../rules/crossfire.md#x027), [X028](../rules/crossfire.md#x028), [X029](../rules/crossfire.md#x029), [X030](../rules/crossfire.md#x030), [X031](../rules/crossfire.md#x031), [X032](../rules/crossfire.md#x032), [X033](../rules/crossfire.md#x033), [X034](../rules/crossfire.md#x034) (34 rules).
<!-- /generated: nature-rules -->

## Where it comes from

The name is taken from **military crossfire**: two guns sited so that their
fields of fire overlap on the same ground. A defender who slips past the first
gun walks straight into the second, because there is no seam between them to
thread. The crossfire is what closes the gap a single gun leaves.

Crossfire rules are TrustSight's second gun. The payload rules (R, H, C, S)
are the first: they fire when a command *resolves* to something recognisable -
a fetch, an execution, a write. An attacker dodges that gun by defeating the
tokenizer, writing a command the analyser cannot reduce to a literal, so the
payload rules see nothing and stay silent. Crossfire is trained on exactly
that ground. It fires on *how* a thing was written rather than on what it
does, so the same evasion that silences the payload rules trips the crossfire
rules instead. Dodging one gun is walking into the other.

This is why a single diff can legitimately produce findings from both
families, scored independently: the payload rule catches what resolved, and
the crossfire rule catches the attempt to keep it from resolving. Evasion and
alarm become the same event, instead of evasion and silence.

The family is a function of refusal, so any tokenizer improvement that
resolves more constructs shrinks its detection surface. That is the intended
way it shrinks - measured per release and recorded, with a changelog
adjudication whenever a technique leaves the family's view.

## What a finding means

- The finding names the evasion technique, not the payload it hid. Read it as
  "this was written so the analyser could not see it", which is evidence on
  its own, whatever was hidden.
- Crossfire pairs with the payload families: crossfire names *how* the thing
  was hidden, a payload rule names *what* it does. Read them together.
- The finding assumes the technique itself is the signal, which is exactly
  why the sandboxed tokenizer exists; where the tokenizer could not read, the
  refusal is what fires.

## See also

- [Sandboxing the Tokenizer](../../explanation/sandboxing-the-tokenizer.md)
- [Crossfire system page](../rules/crossfire.md)
