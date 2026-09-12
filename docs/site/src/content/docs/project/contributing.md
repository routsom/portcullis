---
title: "Contributing"
---

Contributions are Apache-2.0 with DCO sign-off (`git commit -s`); there is no CLA
and no relicensing. Run the same gate CI runs before opening a PR:

```sh
just check   # fmt + clippy -D warnings + cargo-deny + tests + directive checks
```

See
[`CONTRIBUTING.md`](https://github.com/routsom/portcullis/blob/main/CONTRIBUTING.md)
for the Definition of Done and the Prime Directive rules, and
[`SECURITY.md`](https://github.com/routsom/portcullis/blob/main/SECURITY.md)
for private vulnerability reporting (90-day coordinated disclosure).
