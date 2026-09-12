---
title: "Plugins (WIT ABI)"
---

Extensions are **WebAssembly Components** implementing a stable WIT interface,
not dynamically-loaded native code. A plugin built against a 1.x WIT keeps
working across 1.x core releases; the interface is a public API surface under the
semver contract.

The frozen interface lives at
[`wit/portcullis.wit`](https://github.com/routsom/portcullis/blob/main/wit/portcullis.wit).
It defines protocol-neutral types (principal, invocation, decision, tool-result),
a minimal `host` import surface (log, metric — no filesystem, no network, no
process), and two exported hooks:

- **`policy.evaluate`** — decide whether an invocation is allowed;
- **`transform.on-tool-result`** — optionally rewrite a tool result (every change
  is logged by the host).

The WASM component *host* runtime that loads these plugins is the next step; the
ABI is frozen first so third parties can build against a published contract.
