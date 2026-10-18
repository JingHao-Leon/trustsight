<!-- description: Where the crossfire rules come from (a package attacking its own build environment or peers) and what a finding means. -->

# Crossfire: Rule Nature

Mechanics live on the [Crossfire system page](../rules/crossfire.md).

## Where it comes from

The threat model widens from "this package hurts the user" to "this package
hurts the build". A recipe that kills processes, wipes paths, edits files
outside `$pkgdir`, or interferes with other packages' sources is attacking
the shared environment it happens to run in. The name is deliberate: the
damage is collateral and often aimed at the tooling rather than the user.

The rules target writes and destructive operations that escape the sandbox's
intended scope: `rm -rf` on system paths, permissions changes on installed
files, and edits to the source cache other packages rely on.

## What a finding means

- The finding names the out-of-scope target. Read it as a boundary violation,
  not necessarily intent to harm the end user.
- Crossfire pairs heavily with staging, persistence, and obfuscation: its
  role is often to clear the way for another step.
- The rules assume the sandbox held; a crossfire finding is what the package
  tried to do to the environment, which is exactly why the sandbox exists.

## See also

- [Sandboxing the Tokenizer](../../explanation/sandboxing-the-tokenizer.md)
- [Crossfire system page](../rules/crossfire.md)
