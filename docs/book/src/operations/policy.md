# Authorization policy

Policy is ordered, fail-closed RBAC/ABAC. The first matching rule decides; no
match denies. Rules match on tenant, principal, **roles** (RBAC), capability
globs, delegation-chain depth, and **attribute predicates** (ABAC).

```toml
[[policy.rules]]
id = "deny-destructive"
effect = "deny"
matcher = { capabilities = ["*.delete", "*.destroy"] }

[[policy.rules]]
id = "writers-write"
effect = "allow"
matcher = { roles_any = ["writer"] }
```

Decisions are explainable (which rule, and why) for the audit log and future
`policy test` tooling, and cached on the full authorization inputs so repeated
decisions stay off the critical path. Roles and attributes come from each
principal's `[[auth.tokens]]` entry.
