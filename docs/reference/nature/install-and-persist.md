<!-- description: Where the install-and-persistence rules come from (getting code to run beyond the build) and what a finding means. -->

# Install and Persistence: Rule Nature

Mechanics live on the [Install and Persistence system page](../rules/install-and-persist.md).

## Where it comes from

A build that only runs at build time is contained by the sandbox that ran it.
Persistence is how code survives past that: writing a `systemd` unit, a cron
job, a shell profile hook, or a `pacman` hook that re-runs later, so the
execution happens *after* the reviewer has stopped looking and the container
is gone.

The rules cover the standard Linux persistence surfaces a package has no
business installing silently: units and timers, cron and anacron, shell rc
files, pacman hooks, and udev rules. Together they answer "does this package
arrange to run again on its own?".

## What a finding means

- The finding is about the **mechanism**, not the motive: a service unit is
  not inherently malicious, but it is a durable execution path and it must be
  visible on the diff.
- Where the write lands matters more than the write itself: `/etc/...` and
  per-user autostart directories persist; a file inside the build tree does
  not.
- A chain that installs a unit *and* installs a fetch-and-execute script is
  the compound case worth escalating; read the two findings together.

## See also

- [Structural User Rules](../../explanation/structural-user-rules.md); how
  package structure is read
- [Install and Persistence system page](../rules/install-and-persist.md)
