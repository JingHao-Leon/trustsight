<!-- description: Where the corpus-behavioral rules come from (deviation from what the ecosystem normally does) and what a finding means. -->

# Corpus Behavioral: Rule Nature

Mechanics live on the
[Corpus Behavioral system page](../rules/corpus-behavioral.md).

## Where it comes from

Most rules ask "is this pattern dangerous?". The corpus-behavioral rules ask
a different question: "does this package behave like the thousands of benign
packages we have seen?". The model is trained on the benign corpus; what it
flags is **novelty**, the package that does not look like its peers, whether
or not any human named the pattern.

This is the learned layer of TrustSight, and its limits are the corpus's
limits: it can only know normal from the examples in the priors, so a
rare-but-legitimate build can read as novel. It is deliberately a
*mild-signal* contributor that raises suspicion for named rules to
corroborate.

## What a finding means

- The finding says the package deviates from the benign corpus's behaviour,
  with the feature(s) driving it. It is not a named attack.
- A lone novelty finding is weak; novelty plus a concrete rule is the case
  where the corpus adds real value.
- If the priors were trained on a narrow slice, novelty findings will be
  noisy; this is a corpus-provenance question, not a package one.

## See also

- [Corpus and Priors](../../explanation/corpus-and-priors.md)
- [Cold Start and Maturity](../../explanation/cold-start-and-maturity.md)
- [Corpus Behavioral system page](../rules/corpus-behavioral.md)
