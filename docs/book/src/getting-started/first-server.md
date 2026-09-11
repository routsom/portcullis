# Your first proxied server

The example config expects an MCP server reachable at
`http://127.0.0.1:9090/mcp`. In M0–M5 the edge connects to upstreams over
**Streamable HTTP** (spawning stdio servers is the runner's job; see
[ADR-0003](../project/adrs.md)).

Call the gateway like any Streamable HTTP MCP endpoint, with a bearer token:

```sh
curl -s http://127.0.0.1:8080/mcp \
  -H "authorization: Bearer $PORTCULLIS_TOKEN_AGENT" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{}}}'
```

The response carries an `x-portcullis-protocol` header with the negotiated
revision. A request with no token gets `401`; a forged `Host` gets `403`
(DNS-rebinding defence). Scrape usage at `http://127.0.0.1:8080/metrics`.
