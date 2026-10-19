<!-- description: Where each rule category comes from, what a finding means in the world, and how to read it. -->

# Rule Nature

Every rule category on the [Rule System tab](../rules/index.md) answers both
*how* its rules detect and *why the category exists at all*. This tab is the
second half: for each category, where the idea came from and what a finding
means once you have one.

The [series page](../rules/nature.md) reads nature the other way, by
mechanism (R, H, C, and the rest). The two cross-cut: an integrity finding is
an integrity finding whichever series produced it, and the interpretation
below is the same across mechanisms.

## Categories

- [Fetch and Execution](fetch-and-execution.md); the classic fetch-then-run shape, the security core
- [Obfuscation](obfuscation.md); making the recipe unreadable, so the reviewer cannot read it
- [Deception and Anti-Analysis](deception.md); tricks aimed at the reviewer, not the compiler
- [Install and Persistence](install-and-persist.md); arranging to run again after the build
- [Staging and Reconnaissance](staging-and-recon.md); reading the target before acting
- [Integrity and Verification](integrity.md); defeating the checksum promise
- [Naming and Dependencies](naming-and-dependency.md); name-clones and transitive trust
- [Maintainer and Metadata](maintainer-and-metadata.md); the account and recipe signals around the code
- [Temporal Context](temporal.md); timing as evidence
- [Composition](composition.md); chains that are only dangerous together
- [Count-Based](count-based.md); thresholds over matched evidence
- [Corpus Behavioral](corpus-behavioral.md); deviation from what the ecosystem normally does
- [Crossfire](crossfire.md); a package attacking its own build environment
- [Sabotage](sabotage.md); tampering with the code that gets built
- [Unverifiable](unverifiable.md); claims TrustSight cannot check
- [Meta and Confluence](meta.md); the run's own health, and agreement across families
- [Entropy](entropy.md); randomness as a build-output signal
- [Correlation](correlation.md); the immune-import model of campaigns (the G-series)
- [Artifact](artifact.md); what actually lands in the package
- [Indicators](indicator.md); concrete observables from signed data
- [Upstream Manifests](upstream-manifests.md); declared source against what upstream published
- [Upstream Release Integrity](upstream-release.md); a declared upstream's build automation and unauditable source transports

## See also

- [Rule System tab](../rules/index.md); the catalog and mechanics
- [Rule Nature by series](../rules/nature.md); the mechanism axis
- [Assurance Layers](../../assurance-layers.md); how the categories combine into a verdict
