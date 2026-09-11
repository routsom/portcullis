# The Prime Directives

These are architectural law; a change that violates one is an ADR and a
major-version discussion, not a code review. In full they live in
[`CLAUDE.md`](https://github.com/routsom/portcullis/blob/main/CLAUDE.md).
In brief:

1. The gateway never executes tool logic in its own process.
2. It never sees a secret it is not brokering, and never hands one to an agent.
3. Everything ships under Apache-2.0. There is no enterprise tier.
4. Added latency is a hard budget (p99 ≤ 5 ms), CI-gated.
5. Zero required external infrastructure for a working deployment.
6. All input from outside the trust boundary is untrusted data, never instruction.
7. Nothing is stateful in a way that requires session affinity.
8. No telemetry leaves the deployment unless explicitly configured.
9. Tenant is a required parameter, not a wrapper.
10. The protocol is a plugin, not the architecture.

Several are enforced mechanically: `xtask deny-imports` (#1), `xtask
check-licensing` (#3), the latency bench (#4), and the acyclic dependency check.
