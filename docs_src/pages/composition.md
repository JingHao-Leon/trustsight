<!-- description: Rules that fire when distinct kinds of finding co-occur. H027 and H043 are weight-0 annotations; H098 is the deliberate weight-bearing exception. -->

# Composition

Where these rules come from and what a finding means: [Rule Nature](../nature/composition.md).

Distinct kinds of finding co-occurred. The combination is the signal.

H027 and H043 carry weight 0 by design: the points are already on the board
from the rules that fired, and adding a score for the combination would
double-count what those rules already scored. H098 is the deliberate
exception. A package that both impersonates a popular name and redirects
its dependencies or source is the attack H029 exists to surface, so the
combination carries its own weight rather than relying on the sum of its
parts. Its members still score individually; the cluster stacks on top by
design, the same safety-first choice the X007 crossfire cluster makes.

H027 counts distinct capability `category` values across one diff. H043
counts distinct kill-chain stages. H098 counts distinct naming/deception
signals. None is a detection on its own: they annotate findings that other
rules produced.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---
