<!-- description: Where the staging-and-recon rules come from (reading the target before acting) and what a finding means. -->

# Staging and Reconnaissance

Mechanics live on the [Staging and Reconnaissance system page](../rules/staging-and-recon.md).

<!-- generated: nature-rules -->
**Rules in this nature:** [C025](../rules/staging-and-recon.md#c025), [C028](../rules/staging-and-recon.md#c028), [H007](../rules/staging-and-recon.md#h007), [H010](../rules/staging-and-recon.md#h010), [H038](../rules/staging-and-recon.md#h038), [H040](../rules/staging-and-recon.md#h040), [H042](../rules/staging-and-recon.md#h042), [H076](../rules/staging-and-recon.md#h076), [H085](../rules/staging-and-recon.md#h085), [R058](../rules/staging-and-recon.md#r058) (10 rules).
<!-- /generated: nature-rules -->

## Where it comes from

The analogy is **casing the joint**: the burglar walks the block before the
break-in, memorises the locks, notes where the valuables are and when no one
is home. It is the oldest military idea too - reconnaissance before the
assault, because knowing the terrain is half the operation.

Before an attacker exfiltrates or pivots, they look around in exactly this
way: environment variables, `whoami`, hostnames, cloud metadata endpoints, SSH
keys, wallets, browser stores. In a build container this reconnaissance is a
written-down step, so it is auditable. The rules cover the read-the-target
behaviours that have no place in building a package: probing the metadata
service, walking credential paths, and staging files for a later fetch.

Not every `env` is recon; the rules target the recognisable credential and
cloud-metadata shapes rather than generic introspection. The value is that a
recon step turns an otherwise-ambiguous fetch into a deliberate
look-then-take sequence.

## What a finding means

- The finding names the target being read (a metadata IP, a credential path,
  a wallet directory). Read it as intent evidence: the package is
  accumulating material it was not asked to touch.
- Recon alone may be weight of evidence rather than a verdict; recon followed
  by a network send is the pattern to escalate.
- Some of these rules co-fire with crossfire and exfiltration families by
  design; the pairing is the signal.

## See also

- [Cross-File Consistency](../../explanation/cross-file-consistency.md)
- [Staging and Reconnaissance system page](../rules/staging-and-recon.md)
