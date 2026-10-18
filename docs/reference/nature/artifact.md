<!-- description: Where the artifact rules come from (what actually lands in the package) and what a finding means. -->

# Artifact: Rule Nature

Mechanics live on the [Artifact system page](../rules/artifact.md).

## Where it comes from

The final question of any package is "what files does the user end up with?".
The artifact family reads `$pkgdir` after the build: what was installed,
where, with what permissions, and whether it matches what the recipe
declared. It is the last checkpoint before the tarball ships, and it sees the
result of every step that came before.

This is why artifact findings often confirm what earlier families suspected:
an execution path named in the shell becomes a file in the package, a write to
`/etc` becomes an entry in the installed tree.

## What a finding means

- The finding describes the installed file or permission and why it is
  notable (unexpected location, world-writable, outside declared `backup`).
- Artifact findings are concrete and low-ambiguity: the file is there, and
  the reviewer can decide whether it belongs.
- When an artifact finding matches an earlier shell finding, the pair is the
  strongest form of evidence TrustSight produces.

## See also

- [Structural User Rules](../../explanation/structural-user-rules.md)
- [Artifact system page](../rules/artifact.md)
