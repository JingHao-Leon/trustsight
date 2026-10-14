<!-- description: Why TrustSight flags packages that merely touch a neighbourhood under a campaign alert - and why that flag is reported, not scored. -->

# Neighborhood Elevation

When a campaign is active, the packages *around* it are worth a glance even
if they are not part of it. **Neighborhood elevation** is how TrustSight
raises them - carefully.

## Where it comes from

**Cytokine signaling.** An alerted immune cell releases signals that raise
the readiness of the surrounding tissue, so a threat is met faster. It is
local, temporary, and useful.

The failure mode is a **cytokine storm**: unbounded elevation damages the
very tissue it was meant to protect. So the whole design here is the cap.

## What happens

While a campaign is active (see [Campaign Alert Mode](campaign-alert-mode.md)),
a package in the window that *gains* a host or domain in the campaign's
scope - without itself being corroborated - gets one finding, **G006
(Neighborhood Under Campaign Alert)**, weight 0.

It is **reported, not scored**. "This package touches a neighbourhood that is
under alert" names a context, not a behaviour. Scoring it would hand an
attacker a lever: touch a host that is *already* hot and your package looks
worse for reasons you did not cause.

Only *gained* hosts count. A package that already had the host is not newly
elevated, so nothing changes for it.

## Why weight 0 in v1

Scoring this needs a number nobody has yet: how often *benign* packages touch
a hot neighbourhood during a real campaign window (CDNs, `github.io`, shared
build hosts). Until that is measured, a score here is a guess that would
inflate exactly the packages an attacker wants inflated. The weight-0 report
is the instrumentation that will eventually answer the question.

## Related

- [Campaign Alert Mode](campaign-alert-mode.md)
- [Kinds of Alerts](kinds-of-alerts.md)
