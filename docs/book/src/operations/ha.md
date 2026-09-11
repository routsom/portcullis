# High availability

Sessions are **stateless**: a signed session token carries its own routing hint
and resumption cursor, so any node can serve any request — no sticky load
balancer, no shared session store. Configure a shared signing key across nodes:

```toml
[session]
secret_env = "PORTCULLIS_SESSION_SECRET"
```

A token minted by one node verifies on any other node holding the same key. Kill
a node mid-session and the next request succeeds on another node with zero
client-visible error — exercised by the active-active failover test.
