# Contributing to portcullis

Thank you for helping build an MCP gateway that is safe to put in front of
untrusted tools. A few things are non-negotiable; the rest is ordinary good
engineering.

## License and sign-off

- All contributions are licensed under **Apache-2.0** (see `LICENSE`). There is
  no CLA and no relicensing (CLAUDE.md §14, Directive #3).
- Every commit must be **signed off** under the [Developer Certificate of
  Origin](https://developercertificate.org/). Add a `Signed-off-by` trailer:

  ```
  git commit -s
  ```

  which appends `Signed-off-by: Your Name <you@example.com>`.

## Before you open a PR

Run the same gate CI runs:

```
just check
```

which is `fmt` + `clippy -D warnings` (pedantic) + `cargo deny` + tests +
directive checks (`deny-imports`, `check-licensing`, `dep-graph`, `api-diff`).

See the **Definition of Done** in `CLAUDE.md` §13. In short:

- Tests cover the failure case, not just the happy path.
- If the hot path changed, run `just bench` and put the numbers in the PR body.
- Update `docs/` and doc comments in the same commit.
- Add a `CHANGELOG.md` entry written for an operator.
- No new default that is less safe than the previous default.

## The Prime Directives

`CLAUDE.md` §2 lists ten architectural laws (no in-process execution, no
enterprise tier, hard latency budget, zero required infra, …). A PR that
violates one is rejected regardless of how useful it is. If you believe a
directive needs to change, that is an ADR (`docs/adr/`) and a major-version
discussion - open an issue first.

## Security review

Any change touching a trust boundary must answer the six questions in
`CLAUDE.md` §12 in the PR body, and update `docs/threat-model.md` in the same PR.

## Commits

Small, reviewable commits, one concern each. The message explains *why*. Do not
hand-edit `CHANGELOG.md` once changelog automation exists; until then, an
operator-facing entry per user-visible change is expected.

## Reporting security issues

Do not open a public issue for a vulnerability. See `SECURITY.md`.
