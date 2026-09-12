# Your first proxied server

This is a complete, copy-pasteable walkthrough: you'll stand up a tiny MCP
server, put portcullis in front of it, make real calls, and watch the security
controls and metrics work. It takes about five minutes.

In M0-M5 the edge connects to upstreams over **Streamable HTTP** (spawning stdio
servers is the runner's job; see [ADR-0003](../project/adrs.md)), so we'll use a
small HTTP echo server as the upstream.

## 1. An upstream to proxy

Save this ~20-line echo MCP server as `echo_mcp.py`. It answers `initialize`,
`tools/list`, and `tools/call`:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        method, rid = req.get("method", ""), req.get("id")
        if method == "initialize":
            result = {"protocolVersion": req.get("params", {}).get("protocolVersion", "2026-07-28"),
                      "serverInfo": {"name": "echo", "version": "0"}, "capabilities": {}}
        elif method == "tools/list":
            result = {"tools": [{"name": "echo", "description": "Echoes its arguments",
                                 "inputSchema": {"type": "object"}}]}
        else:
            result = {"echoed_method": method, "echoed_params": req.get("params")}
        body = json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", 9090), Handler).serve_forever()
```

Run it (leave it running in its own terminal):

```sh
python3 echo_mcp.py
```

## 2. A minimal config

Save this as `portcullis.toml`. It's the smallest useful gateway: one HTTP
listener, one authenticated principal, one upstream. (No policy yet - that's the
[configuration reference](./configuration.md); here everything authenticated is
allowed.)

```toml
[server.http]
bind = "127.0.0.1:8080"
allowed_hosts = ["127.0.0.1:8080", "localhost:8080"]

[[auth.tokens]]
token_env = "PORTCULLIS_TOKEN_AGENT"   # the token *value* comes from this env var
principal = "agent-1"
tenant    = "default"
upstream  = "echo"

[[upstream]]
name = "echo"
url  = "http://127.0.0.1:9090/mcp"
```

## 3. Provide the token

The config names an env var; the secret value never lives in the file:

```sh
export PORTCULLIS_TOKEN_AGENT="s3cr3t-agent-token"
```

## 4. Check it with `doctor`

```sh
portcullis doctor --config portcullis.toml
```

```text
portcullis doctor
  ✓ [OK  ] config     parsed portcullis.toml
  ✓ [OK  ] transport  enabled: http
  ✓ [OK  ] auth       1 principal token(s) resolved
  ! [WARN] session    ephemeral signing key (single-node only; set session.secret_env for HA)
  ✓ [OK  ] upstream   echo reachable (501 Not Implemented)
  ✓ [OK  ] clock      skew ~0s vs echo
  ! [WARN] sandbox    non-Linux host: sandboxed execution unavailable (M1 requires Linux namespaces)

healthy (warnings are non-fatal)
```

> The two warnings are expected here: no shared session key (fine for one node),
> and no Linux sandbox on macOS. `echo reachable (501)` is normal - the echo
> server only answers `POST`, and any HTTP response proves connectivity.

## 5. Run the gateway

```sh
portcullis serve --config portcullis.toml
```

## 6. Make a call

`initialize`, with the bearer token. Note the response's
`x-portcullis-protocol` header - the gateway negotiated the revision:

```sh
curl -si http://127.0.0.1:8080/mcp \
  -H "authorization: Bearer $PORTCULLIS_TOKEN_AGENT" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{}}}'
```

```text
HTTP/1.1 200 OK
content-type: application/json
x-portcullis-protocol: 2026-07-28

{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28","serverInfo":{"name":"echo","version":"0"},"capabilities":{}}}
```

Now a `tools/call`. The arguments pass through untouched - the gateway routes and
relays, it does not rewrite payloads:

```sh
curl -s http://127.0.0.1:8080/mcp \
  -H "authorization: Bearer $PORTCULLIS_TOKEN_AGENT" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hello"}}}'
```

```text
{"jsonrpc":"2.0","id":2,"result":{"echoed_method":"tools/call","echoed_params":{"name":"echo","arguments":{"msg":"hello"}}}}
```

## 7. Watch the guardrails

The same request **without a token** is rejected before it reaches the upstream -
there is no `--no-auth`:

```sh
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8080/mcp \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}'
```

```text
HTTP 401
```

And a request carrying a **forged `Host`** (the shape of a DNS-rebinding attack)
is refused - the `Host` isn't in your allow-list:

```sh
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8080/mcp \
  -H "authorization: Bearer $PORTCULLIS_TOKEN_AGENT" \
  -H "host: evil.example.com" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/list"}'
```

```text
HTTP 403
```

## 8. See the metrics

Every request is accounted per tenant, exported locally at `/metrics`:

```sh
curl -s http://127.0.0.1:8080/metrics
```

```text
# HELP portcullis_requests_total Requests handled, by tenant and outcome.
# TYPE portcullis_requests_total counter
portcullis_requests_total{tenant="default",outcome="allowed"} 2
portcullis_requests_total{tenant="default",outcome="denied"} 0
portcullis_requests_total{tenant="default",outcome="upstream_error"} 0
```

Two `allowed` - the `initialize` and the `tools/call`. The rejected requests were
turned away *before* a tenant was established (bad `Host`, no token), so they
aren't attributed to a tenant.

## What you just proved

- ✅ Authenticated calls are relayed faithfully, with protocol negotiation.
- ✅ Unauthenticated and cross-origin requests are refused at the edge.
- ✅ Usage is metered per tenant, locally.

Next: turn on **authorization policy, rate limits, circuit breakers, and a
tamper-evident audit log** in the [configuration reference](./configuration.md).
