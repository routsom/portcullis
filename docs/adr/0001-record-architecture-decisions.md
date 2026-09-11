# ADR-0001: Record architecture decisions

- Status: accepted
- Date: 2026-09-11

## Context

Maintainer decisions need a durable, reviewable record so that future
contributors (human and agent) understand *why* the system is shaped the way it
is, and so that "obvious" ideas that were already decided are not relitigated
(CLAUDE.md §14, §16).

## Decision

We keep Architecture Decision Records in `docs/adr/`, numbered sequentially and
immutable once merged. A decision that changes another is a **new** ADR that
marks the old one superseded; we do not edit accepted ADRs in place.

Each ADR states context, the decision, and its consequences. Prime Directive
changes (CLAUDE.md §2) must be an ADR and a major-version discussion, never a
quiet code change.

## Consequences

- The ADR log is the canonical history of architectural intent.
- Reverting a decision leaves a visible trail (a superseding ADR), not a silent
  deletion.
