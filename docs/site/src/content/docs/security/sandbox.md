---
title: "Sandboxing & the runner"
---

Tool logic runs in `pc-runner`, one process per invocation, never in the edge
(Directive #1). On Linux the runner establishes, in the forked child before
`exec`:

- fresh **user / mount / net / uts / ipc namespaces** (an empty network
  namespace makes cloud metadata and the broker unreachable *by construction*);
- **id mapping** to an unprivileged uid via the user namespace;
- a **read-only root**;
- a **landlock** filesystem ruleset limited to the spec's declared paths;
- **no-new-privileges**; and
- a **seccomp** filter from an operator-owned, reviewed JSON profile.

This is Linux kernel machinery with no portable equivalent. On other platforms
the runner returns `Unsupported` and **fails closed** — it never runs a tool
without a sandbox.

:::caution[Verification status]
The Linux backend is verified only in Linux CI and the red-team escape suite. The
known gap before certification is a `clone`-based launcher for a correct PID
namespace. See [ADR-0005](../project/adrs.md).
:::
