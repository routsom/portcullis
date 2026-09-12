# Rate limits & circuit breakers

<figure class="pc-figure">
  <img src="../img/request-lifecycle.svg" alt="the request lifecycle through the edge, from origin check to audit">
  <figcaption>The request lifecycle. <strong>Rate limiting</strong> (stage 4) and the <strong>circuit breaker</strong> (stage 6) bracket the policy decision; both are skipped when unconfigured, so the passthrough path stays fast.</figcaption>
</figure>

**Rate limiting** is a token bucket per `(tenant, principal, capability)`:

```toml
[rate_limit]
capacity = 50        # burst
refill_per_sec = 10  # sustained
```

An exhausted bucket returns `429`.

**Circuit breakers** are per upstream. After `failure_threshold` consecutive
failures the breaker opens and requests get `503`; after `cooldown_ms` a single
half-open probe decides whether to close or re-open. Upstream 5xx and transport
errors count as failures.

```toml
[circuit_breaker]
failure_threshold = 5
cooldown_ms = 5000
```

Both are skipped entirely when unconfigured, so the passthrough path keeps its
M0 cost.
