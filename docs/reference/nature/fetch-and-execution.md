<!-- description: Where the fetch-and-execution rules come from (the classic supply-chain attack shape) and what an H finding means. -->

# Fetch and Execution: Rule Nature

Mechanics live on the [Fetch and Execution system page](../rules/fetch-and-execution.md).

## Where it comes from

This is the oldest and best-understood attack in the PKGBUILD space: the build
recipe reaches out to the network, pulls something down, and runs it, so the
code that executes is not the code a reviewer read. It is how `curl | bash`
works and how a hijacked source URL turns a reviewer's diff into a smokescreen.

The rules are ordered by how directly they express that one shape, from the
literal pipe to the same effect spread across lines with variables, base64,
or a helper. The H-series is the security core of TrustSight: built first,
calibrated hardest, and the one the fire-rate work is measured against.

## What a finding means

- The rule names the **use** (fetch, then execute), not proof of malice. A
  package that genuinely must build from a download can say so; the point is
  that the reviewer sees it and it cannot hide in the noise.
- Findings are line-anchored and come with the matched text, so the reviewer
  reads the actual recipe rather than trusting a label.
- Fetch and execute in one line, across lines, via a variable, or through a
  package manager are the same finding family; the cross-file and
  reducing-the-h-series work exists so the set stays small enough to audit.

## See also

- [Fire Rates](../../explanation/fire-rates.md); how H rules are calibrated
- [Reducing the H-Series](../../explanation/reducing-the-h-series.md)
- [Fetch and Execution system page](../rules/fetch-and-execution.md)
