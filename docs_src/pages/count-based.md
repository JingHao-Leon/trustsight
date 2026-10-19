<!-- description: Rules that fire when a count of same-kind indicators crosses a fixed threshold within one artifact or one cluster. -->

# Count-Based

Where these rules come from and what a finding means: [Rule Nature](../nature/count-based.md).

A count crossed a fixed threshold. What separates these from
[composition](composition.md) is that the count is over indicators of one
kind rather than over distinct kinds, and what separates them from
[corpus behavioral](corpus-behavioral.md) is that the threshold is a
configured constant rather than a deviation from a learned baseline.

H036 counts obfuscation indicators on one line. H030 counts added
dependencies weighted by rarity. H045, H052 and H055 count packages in a
cluster. Every threshold is configurable under `[thresholds]`, and every
one was set against the benign corpus rather than chosen.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---
