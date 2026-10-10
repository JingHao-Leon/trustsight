<!-- description: The layers object in the report: detection and coverage per category, the statuses, and a worked JSON example. -->

# Part 3: Reporting

This page answers: what does the `layers` object in a report actually say?

The report groups findings by evidence category and, for each category, records
two independent facts: whether anything was **detected**, and how far the
category could be **assessed**.

## Detection and coverage

- **Detection** is `fired` when a finding in that category was produced, and
  `none` otherwise.
- **Coverage** is `complete` when the category was fully exercised,
  `incomplete` when a coverage gap (a truncated diff, an unresolvable value, a
  partial file) blinded it, and `not_applicable` when the analysis mode cannot
  exercise it at all (L8 cross-package correlation in a single-package
  review).

They are kept separate because a finding must not hide that the same category
was also unread, and an unread category must not hide a finding.

## Reading the statuses

| Category | Detection | Coverage | Meaning |
|---|---|---|---|
| L3 Payload signature | fired | complete | A rule such as `R001` matched a changed command shaped like `curl ... \| bash`. Positive evidence of a known pattern. |
| L3 Payload signature | none | complete | The input was fully available, no rule in this category matched. **Not** a safety certificate. |
| L1-L4 | any | incomplete | A `source=` value is computed dynamically or the diff was truncated, so the category was not fully assessed. |
| L8 Campaign correlation | none | not_applicable | A single-package review has no cross-package input; the check did not run. |

For one release the object also carries a derived `status`
(`fired`/`passed`/`unreadable`/`not_exercised`) that collapses the two
dimensions for back-compat consumers; new consumers should read `detection`
and `coverage`.

## A worked JSON example

```json
"layers": {
  "L3": {"name": "Payload signature", "detection": "fired",
         "coverage": "complete", "status": "fired", "findings": ["R001"]},
  "L1": {"name": "Structural coherence", "detection": "none",
         "coverage": "incomplete", "status": "unreadable", "findings": []},
  "L8": {"name": "Campaign correlation", "detection": "none",
         "coverage": "not_applicable", "status": "not_exercised", "findings": []}
}
```

Read it as: a payload-signature check fired; the structural-coherence check
could not be fully assessed (so its silence is not evidence); cross-package
correlation did not apply to this run.

## The verdict sentence

When findings score, the verdict names the **fired evidence categories**:

```
Evidence categories fired: L3 (Payload signature). Review the diff before building.
```

This answers "which kinds of evidence produced findings". It does not claim a
sequence - a category's label is where the finding was produced, not a stage
an attacker reached.

## The terminal

`inspect --verbose` prints a single line beside the panel listing the
categories whose status is not `passed` and the count of boundaries that
forbid a clean verdict - the same projection the JSON carries.

## The boundary, beside the layers

The layer profile projects findings; the **boundary** list projects what the
run could *not* conclude - one object per coverage gap and per W rendering,
each with `forbids_clean` (see
[the security model](../security/what-a-result-claims.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)).
`incomplete` coverage and a `forbids_clean` boundary are two views of the same
shortfall, and both travel to every surface.

## See Also

- [Part 2: How to add a useful new detector](diversity.md)
- [Part 4: Tests and adversarial evaluation](enforcement.md)
- [Report schema](../reference/report-schema.md) - the exact fields
