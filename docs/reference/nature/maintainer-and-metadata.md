<!-- description: Where the maintainer-and-metadata rules come from (account and recipe-metadata hygiene) and what a finding means. -->

# Maintainer and Metadata: Rule Nature

Mechanics live on the
[Maintainer and Metadata system page](../rules/maintainer-and-metadata.md).

## Where it comes from

Most PKGBUILD attacks are delivered through an *account*, not a clever
parser: a new maintainer, a fresh key, a `pkgver` that lies, a commit that
touches the metadata and nothing else. The T-series reads the human and
recipe metadata around the code, because a takeover usually shows there
first.

The rules look at the maintainer key's age and reputation, unusual `pkgver`
and `pkgrel` moves, checksum work that rewrites history, and metadata that
contradicts the recipe. None of this is proof; the value is that a metadata
anomaly makes the *code* diff worth a second read, which is exactly the
situation a silent maintainer swap creates.

## What a finding means

- The finding is about a signal on the account or the metadata, dated and
  attributed, not an accusation about the package's contents.
- A new maintainer plus a code change in the same window is the pattern;
  either alone is routine.
- These rules feed the blast-radius and novelty scoring, so they often move a
  run's band without being dramatic on their own.

## See also

- [Cold Start and Maturity](../../explanation/cold-start-and-maturity.md)
- [Maintainer and Metadata system page](../rules/maintainer-and-metadata.md)
