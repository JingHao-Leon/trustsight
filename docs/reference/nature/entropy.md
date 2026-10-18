<!-- description: Where the entropy rules come from (statistical randomness as a build-output signal) and what a finding means. -->

# Entropy: Rule Nature

Mechanics live on the [Entropy system page](../rules/entropy.md).

## Where it comes from

Legitimate build output has structure: source text, logs, compiled code.
Encrypted or compressed payloads do not, and high-entropy blobs written by a
recipe are a classic way to smuggle a payload past a reviewer who only reads
the shell. The entropy rules measure the randomness of build-adjacent data
and flag the blob that does not belong.

This is a probabilistic family: the finding is a statistical property of the
data, not a decode. It is a lead for a human, not a verdict, and it is
score-bounded accordingly.

## What a finding means

- The finding reports an entropy anomaly with the location; false positives
  are expected on legitimately compressed assets, which is why it is a
  weak weighted signal.
- High entropy plus a fetch or an obfuscation step is the combination worth
  acting on; high entropy alone may be a bundled archive.
- Because the ceiling is statistical, treat it as "look here", not "this is
  malformed".

## See also

- [Why Static Analysis](../../explanation/why-static-analysis.md)
- [Entropy system page](../rules/entropy.md)
