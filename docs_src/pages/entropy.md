<!-- description: E-series rules read the added content as a distribution - a statistical outlier is suspicion, never a verdict, and the thresholds ship empty until the corpus sets them. -->

# Entropy

Where these rules come from and what a finding means: [Rule Nature](../nature/entropy.md).

E rules read the **distribution** of the added content. No patterns, no
refusal semantics: an attacker who writes resolvable-but-obfuscated code
defeats the X-series' refusal coupling, but a distribution does not care
*why* the content is strange.

This is the statistical twin of [Crossfire](crossfire.md): X catches what
the tokenizer refuses to fold, E catches what folds cleanly but weirdly.

This is a reference page. For how weight and scope work, see
[Rule System](system.md).

## Reading an E finding

- It is **suspicion, never a verdict**. An E finding never reaches FATAL.
- Its thresholds ship **empty**: every E rule is silent until an operator or
  the calibration job sets the threshold from the first corpus measurement.
  The benign fire rate is the published number once measured.
- It names the measured value, never the content.

---
