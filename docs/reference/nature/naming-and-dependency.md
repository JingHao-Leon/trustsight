<!-- description: Where the naming-and-dependency rules come from (name-clones and dependency injection) and what a finding means. -->

# Naming and Dependencies: Rule Nature

Mechanics live on the
[Naming and Dependencies system page](../rules/naming-and-dependency.md).

## Where it comes from

Two early-stage attacks, both about identity or a much smaller feedstock
issue than a shell pipeline:

- **Typosquatting and name-cloning.** A package name that is a near-miss of a
  far more popular one (or the same name under the wrong base) relies on the
  reader's eye, not on any code. G005, the impersonation campaign rule, is the
  collective form: one account publishing many such clones.
- **Dependency injection.** Adding a dependency is how you get *someone else's*
  install hook and code into a user's system. A new dependency that is not a
  real upstream, or a version pin that redirects to an unowned repo, smuggles
  in code the package itself never wrote.

## What a finding means

- Name findings are about the relationship between this name and a famous
  one; the finding carries both, so the reviewer sees the target being
  imitated.
- A single odd name is weak; a burst from one maintainer is G005.
- Dependency findings are about trust transitivity: the reviewer approved
  *this* package, not the transitive one the recipe just added.

## See also

- [Correlation: Rule Nature](correlation.md); the G005 campaign form
- [Naming and Dependencies system page](../rules/naming-and-dependency.md)
