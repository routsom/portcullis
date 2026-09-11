# Install & first run

## Build from source

```sh
git clone https://github.com/routsom/portcullis
cd portcullis
cargo build --release   # produces ./target/release/portcullis
```

Requires a stable Rust toolchain (edition 2024, rustc ≥ 1.85). The full
developer gate is `just check` (fmt, clippy, cargo-deny, tests, directive checks).

## Provide secrets via the environment

portcullis never stores secret *values* in config — only the names of the
environment variables that hold them (Directive #2):

```sh
export PORTCULLIS_TOKEN_AGENT="$(openssl rand -hex 32)"
export PORTCULLIS_SESSION_SECRET="$(openssl rand -hex 32)"
```

## Check your setup

```sh
portcullis doctor --config examples/portcullis.toml
```

`doctor` diagnoses config, upstream connectivity, clock skew, and sandbox
availability in one command, and exits non-zero on a failing check.

## Run

```sh
portcullis serve --config examples/portcullis.toml
```

Next: [Your first proxied server](./first-server.md).
