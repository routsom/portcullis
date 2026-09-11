# Threat model

The full, versioned threat model — assets, trust boundaries, per-entry-point auth,
threats and mitigations, and residual risks — is maintained alongside the code at
[`docs/threat-model.md`](https://github.com/routsom/portcullis/blob/main/docs/threat-model.md)
and updated in the same PR as any architectural change.

Every change touching a trust boundary must answer six questions (what new data
crosses a boundary and who controls it; worst case under full attacker control;
any path from tool output into a decision or a shell; any new secret-read path;
what is logged; which traceability row is affected).
