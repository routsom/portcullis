# Protocol translation (OpenAPI)

An OpenAPI 3 document is translated **once, at load time**, into a table of
invocable capabilities — never interpreted per request, which is how the gateway
stays inside the latency budget where others spend 100–300 ms.

```sh
portcullis translate openapi --file examples/openapi-petstore.json --find "get a pet"
```

Each operation becomes a tool with a derived name, a description, a merged JSON
Schema for its arguments, and an HTTP binding (method, path template, parameter
locations, body). Because the output is a standard tool definition, translated
capabilities flow straight into the catalog, the policy engine, and the poison
scanner. A gRPC adapter is on the roadmap.
