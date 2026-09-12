---
title: "The capability facade & tokens"
---

Statically listing every tool to a model inflates input tokens on every turn.
The facade instead exposes `gateway.find(query)` — returning matching tools
**with their full, invocable schemas** — and `gateway.find_and_invoke`, which
selects and dispatches in the same round trip.

Whether that saves tokens depends on the workload, so the facade **measures it**
and recommends static exposure when it does not win. A large catalog with a
narrow per-turn need is where it shines (> 50% reduction); a handful of tools is
not. See the [token report](https://github.com/routsom/portcullis/blob/main/docs/token-report.md)
and `portcullis translate ... --find`.
