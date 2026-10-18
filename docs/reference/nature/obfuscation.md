<!-- description: Where the obfuscation rules come from (making the recipe unreadable) and what a finding means. -->

# Obfuscation: Rule Nature

Mechanics live on the [Obfuscation system page](../rules/obfuscation.md).

## Where it comes from

Fetch-and-execute is visible if a reviewer can read the command. Obfuscation
exists to defeat exactly that reading: base64 or hex decode before execution,
string reassembly, `eval`, `printf` into a shell, or an interpreter fed a
blob. In PKGBUILDs the honest cases are rare, because the source tarball and
its checksum already exist; a recipe that hides its text is hiding it from
the one person positioned to approve it.

The rules therefore treat concealment itself as evidence, not as a
implementation detail to decode. TrustSight does **not** try to reverse the
obfuscation; it flags that the recipe is reaching for a decoder and lets the
reviewer decide.

## What a finding means

- The finding names the concealment technique (base64, hex, eval, string
  slicing), with the matched fragment. It is about the technique's presence,
  which is decidable statically, not about what the blob would do.
- Obfuscation next to a network call is the high-value pairing; obfuscation
  alone may still be a build quirk, but it is never nothing in a recipe whose
  checksums a reviewer is supposed to verify.
- Findings here frequently co-fire with fetch-and-execution; that pairing is
  the intended escalation, not a duplicate.

## See also

- [Why Static Analysis](../../explanation/why-static-analysis.md); why the
  blob is not decoded
- [Obfuscation system page](../rules/obfuscation.md)
