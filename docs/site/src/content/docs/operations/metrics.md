---
title: "Metrics & observability"
---

Metrics are on by default and **exported locally only** (Directive #8). The HTTP
listener serves Prometheus text at `/metrics`:

```text
portcullis_requests_total{tenant="acme",outcome="allowed"} 128
portcullis_requests_total{tenant="acme",outcome="denied"} 3
portcullis_requests_total{tenant="acme",outcome="upstream_error"} 1
```

Counts are per tenant, making usage/cost tenant-attributable. Bind the listener
to a trusted interface if you expose metrics.

Each outcome is recorded at **stage 8** of the
[request lifecycle](./policy.md) — the same point the audit entry is written,
after the response is relayed.

Structured logging uses `tracing` throughout (structured fields, never string
interpolation of user data). An OTLP exporter is on the roadmap; nothing leaves
the process today.
