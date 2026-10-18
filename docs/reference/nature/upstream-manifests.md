<!-- description: Where the upstream-manifest rules come from (declared source versus what is fetched) and what a finding means. -->

# Upstream Manifests: Rule Nature

Mechanics live on the
[Upstream Manifests system page](../rules/upstream-manifests.md).

## Where it comes from

Upstream projects increasingly publish metadata about themselves (release
manifests, SBOMs, signature files, `.SRCINFO`-like declarations). The
upstream-manifest rules compare what a recipe claims about its source against
what the upstream actually published: a version that does not exist, a hash
that does not match the manifest, a source name upstream never released.

The point is to catch the recipe that is internally consistent but
*externally* wrong: checksums that verify against the wrong artifact, or a
`source` array naming a file no upstream release contains. This is the
supply-chain-integrity check turned outward.

## What a finding means

- The finding names the mismatch between the recipe and the upstream
  declaration, with both values.
- A manifest mismatch is often decisive: it means the thing being verified is
  not the thing the upstream intended, regardless of the recipe's own
  consistency.
- These rules need network access to the upstream manifest, so on an offline
  run they report reduced coverage rather than passing silently.

## See also

- [Integrity and Verification: Rule Nature](integrity.md)
- [Upstream Manifests system page](../rules/upstream-manifests.md)
