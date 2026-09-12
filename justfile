# portcullis task runner. CI runs exactly these recipes (CLAUDE.md §10); if it
# passes locally and fails in CI, that is a bug in this file, not a reason to add
# a CI-only step.

# Make the user-local cargo bin (rustup, cargo-deny, just) visible to recipes.
export PATH := env_var('HOME') / '.cargo/bin:' + env_var('PATH')

# Default: the full gate.
default: check

# fmt + clippy -D warnings + deny + test + directive checks + api-diff (§10).
check: fmt-check clippy deny test xtask-all
    @echo "✓ all checks passed"

# Apply formatting.
fmt:
    cargo fmt --all

# Verify formatting without changing files.
fmt-check:
    cargo fmt --all -- --check

# Lint with pedantic clippy; warnings are errors.
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Unit + integration tests across the workspace.
test:
    cargo test --workspace

# Integration tests that spin real sandboxes (Linux user namespaces, M1+).
test-e2e:
    cargo test --workspace --test '*' -- --include-ignored

# Latency benchmark against the budgets in §6 (release build for realism).
bench:
    PORTCULLIS_BENCH_TOKEN=bench-token cargo run --release -q -p pc-bench-latency

# Directive-enforcing checks (deny-imports, check-licensing, dep-graph, api-diff).
xtask-all:
    cargo run -q -p xtask -- all

# Supply-chain: advisories, licenses, bans, sources.
deny:
    cargo deny check

# cargo-audit equivalent via cargo-deny.
audit:
    cargo deny check advisories bans sources

# Build, then run doctor against the example config.
doctor:
    cargo run -q -p pc-cli -- doctor --config examples/portcullis.toml

# cargo-fuzz targets land with M1/M3.
fuzz target:
    @echo "fuzz target '{{target}}' arrives with M1/M3"

# MCP spec conformance across supported revisions.
conformance:
    cargo run -q -p pc-conformance

# Build the documentation site (Astro Starlight).
docs:
    cd docs/site && npm ci && npm run build

# Serve the docs locally with live reload.
docs-serve:
    cd docs/site && npm install && npm run dev
