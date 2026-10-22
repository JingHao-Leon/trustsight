<!-- description: Where the sabotage rules come from (tampering with the goods that ship) and what a finding means. -->

# Sabotage

Mechanics live on the [Sabotage system page](../rules/sabotage.md).

<!-- generated: nature-rules -->
**Rules in this nature:** [S001](../rules/sabotage.md#s001), [S002](../rules/sabotage.md#s002), [S003](../rules/sabotage.md#s003), [S004](../rules/sabotage.md#s004), [S005](../rules/sabotage.md#s005), [S006](../rules/sabotage.md#s006), [S007](../rules/sabotage.md#s007), [S008](../rules/sabotage.md#s008) (8 rules).
<!-- /generated: nature-rules -->

## Where it comes from

Picture a **courier who swaps the parcel**. They do not add anything to your
order; they take the genuine goods out and put something else in, so the seal
you checked at the door was real and the box you open is not. Sabotage is the
subtlest class for exactly this reason: the package does not add its own
payload, it *alters* or *misrepresents* what it ships, so the tarball a user
finally installs is not the tarball the upstream author published. Patching
source silently, rewriting generated files, replacing a binary after build, or
shipping a file that never appears in `source` are all ways to make the
artifact lie about its provenance.

Sabotage is where the "verify the checksums" advice breaks down from the
*inside*: even a perfect source hash cannot help if the recipe then mutates
the result. The rules therefore compare what was declared with what is
installed.

## What a finding means

- The finding says the installed artifact diverges from its stated source or
  declared files.
- Because the divergence is by design legitimate in many packaging tasks
  (distro patches exist), these rules read the *undeclared* and *post-build*
  cases as the suspicious ones.
- A sabotage finding next to a weakened checksum is the combination that
  matters most; each makes the other credible.

## See also

- [Integrity and Verification](integrity.md)
- [Sabotage system page](../rules/sabotage.md)
