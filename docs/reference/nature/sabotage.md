<!-- description: Where the sabotage rules come from (tampering with the code that gets built) and what a finding means. -->

# Sabotage: Rule Nature

Mechanics live on the [Sabotage system page](../rules/sabotage.md).

## Where it comes from

The subtlest class: the package does not add its own payload, it *alters* or
*misrepresents* what it ships, so the tarball a user finally installs is not
the tarball the upstream author published. Patching source silently,
rewriting generated files, replacing a binary after build, or shipping a
file that never appears in `source`: all ways to make the artifact lie about
its provenance.

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

- [Integrity and Verification: Rule Nature](integrity.md)
- [Sabotage system page](../rules/sabotage.md)
