# Security policy

portcullis is security-critical infrastructure: it is meant to sit in front of
untrusted tools. We take reports seriously.

## Reporting a vulnerability

- **Do not** open a public issue, PR, or discussion for a suspected
  vulnerability.
- Report privately via GitHub Security Advisories ("Report a vulnerability" on
  the repository's Security tab), or email the maintainers at the address listed
  on the project page.
- Include: affected version/commit, a description, and a minimal reproduction if
  possible.

## Disclosure process

- We follow **90-day coordinated disclosure**. We will acknowledge receipt,
  investigate, and work with you on a fix and a disclosure timeline.
- We request a CVE for anything reachable by an **unauthenticated** party
  (CLAUDE.md §14).

## Scope

In-scope: the gateway binary and crates in this repository - transports, auth,
origin hardening, session handling, routing, and (as they land) the runner,
broker, policy engine, and audit trail.

Out of scope for M0 (documented limitations, not vulnerabilities): sandboxed
execution, egress control, IMDS blackholing, rate/size limits, and policy
evaluation are later milestones. See `docs/threat-model.md` for the current
posture and residual risks.

## Supported versions

Until 1.0, only the latest release (and `main`) receive security fixes.
