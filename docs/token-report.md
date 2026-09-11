# Token report

Meta-tool indirection (a `gateway.find` facade instead of statically listing
every tool) is only worth it when it actually reduces the input tokens a model
pays on every turn (CLAUDE.md §5 row #15). This report records the methodology
and representative numbers. The facade is a **recommendation backed by numbers**,
not a mandate: on workloads where it does not win, the CLI recommends static
exposure.

## Methodology

- Token counts are estimated with a portable heuristic (~4 characters per token
  of a tool's JSON serialization). This is used for *relative* comparisons, which
  are stable under the approximation; it is not a model-specific tokenizer.
- **Static exposure** = the sum of tokens for every tool definition presented up
  front.
- **Facade** = a fixed overhead for the two facade meta-tool schemas
  (`gateway.find`, `gateway.find_and_invoke`) plus the tokens for only the tools
  a query surfaces.
- Implementation: `pc-facade::tokens`. Reproduce with
  `portcullis translate openapi --file <spec> --find "<query>"`.

## Result 1 — small catalog (facade does NOT win)

`examples/openapi-petstore.json`, 5 operations, query `"get a pet"`:

| Path            | Tokens |
|-----------------|-------:|
| Static exposure |    285 |
| Facade          |    405 |
| **Saved**       |  **0** |

With only five small tools, the facade's fixed overhead exceeds the cost of just
listing them. The CLI reports **"static exposure recommended"** — the honest
answer for this workload.

## Result 2 — large catalog, narrow query (facade wins)

A catalog of 200 verbose tools plus one relevant tool, query `"weather"`,
`limit = 3` (covered by the test `facade_saves_tokens_on_narrow_query_over_large_catalog`):

| Path            |     Tokens |
|-----------------|-----------:|
| Static exposure | ~thousands |
| Facade          |   overhead + 3 surfaced tools |
| **Reduction**   | **> 50%** |

This is the regime the facade is designed for: a large tool surface where any
given turn needs only a few tools. Discovery costs **one** hop, not two, because
`gateway.find` returns fully-invocable schemas and `gateway.find_and_invoke`
dispatches in the same round trip.

## Guidance

- Few tools, or every tool needed most turns → **static exposure**.
- Many tools, few needed per turn → **facade**.
- When unsure, measure with `portcullis translate ... --find` and let the
  reported delta decide.

## Status

Token accounting and the facade search/selection are implemented and tested
(`pc-facade`). Live wiring of `gateway.find` / `find_and_invoke` as MCP meta-tools
on the request path lands with the M5 admin/runtime composition; the numbers and
recommendation logic above are final.
