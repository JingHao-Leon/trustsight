<!-- description: Where the deception rules come from (anti-analysis tricks against a human reviewer) and what a finding means. -->

# Deception and Anti-Analysis: Rule Nature

Mechanics live on the [Deception system page](../rules/deception.md).

## Where it comes from

The audience for a PKGBUILD is a human reviewer and, increasingly, a reviewer
with a tool. The deception family is the class of tricks aimed at that
audience rather than at the compiler: homoglyphs and lookalike characters,
right-to-left overrides that reorder displayed text, invisible or
zero-width bytes, and control characters that render differently than they
parse.

These attacks do nothing at build time. Their whole purpose is to make what
the reviewer *sees* differ from what the shell *runs*, which is why they are
read as anti-analysis evidence rather than as build behaviour.

## What a finding means

- The finding is high-confidence by construction: Unicode confusables,
  bidi overrides, and zero-width characters appearing in a build recipe have
  essentially no benign reading, so these rules can weigh heavily.
- The matched text is shown escaped so the reviewer sees the concealed
  character, not a lookalike that hides it.
- Treat a deception finding as an explanation for *other* findings being hard
  to see; it often rides alongside an obfuscated payload.

## See also

- [Why Static Analysis](../../explanation/why-static-analysis.md); how the
  tokenizer sees what the terminal hides
- [Deception system page](../rules/deception.md)
