# tlsdays

Report days until TLS certificates expire across many hostnames **in parallel**.

Built with Rust (`rustls` + `tokio`). Part of the nfltr distributed orchestration tournament (#6).

## Quickstart

```bash
# Check hosts from the command line (text output)
cargo run --release -- github.com google.com

# JSON Lines for scripting
echo 'github.com' | cargo run --release -- --format jsonl

# Table with higher concurrency and a shorter timeout
cargo run --release -- --format table --concurrent 64 --timeout-ms 5000 host1.example host2.example
```

## Install

```bash
cargo install --path .
```

## Usage

```
tlsdays [--format jsonl|table|text] [--timeout-ms N] [--concurrent N] [--port 443] [--strict-fail] HOST [HOST...]
```

Or pipe hosts on stdin (one `host` or `host:port` per line). IPv6 hosts may use bracket notation: `[2001:db8::1]:443`.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `text` | Output format: `jsonl`, `table`, or `text` |
| `--timeout-ms` | `10000` | TCP connect + TLS handshake timeout per host (milliseconds) |
| `--concurrent` | `32` | Maximum parallel host checks |
| `--port` | `443` | Default port when a host omits `:port` |
| `--strict-fail` | off | Exit with code `2` when any host fails (otherwise failures are reported but successful hosts drive `0`/`1`) |

### Output fields (per host)

| Field | Description |
|-------|-------------|
| `host` | Hostname checked |
| `port` | TCP port |
| `days_until_expiry` | Whole days from now until certificate `notAfter` |
| `not_before` | Certificate validity start (RFC 3339) |
| `not_after` | Certificate validity end (RFC 3339) |
| `subject_cn` | Subject common name (if present) |
| `issuer` | Issuer common name (or full issuer DN) |
| `error` | Present when the check failed |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All hosts succeeded and every certificate has ≥ 7 days remaining |
| `1` | All successful hosts are OK, but at least one has &lt; 7 days remaining |
| `2` | At least one host failed (when `--strict-fail` is set), or no successful hosts |

## Development

```bash
cargo test --release
cargo test --release --features live-tests   # requires network
cargo clippy --no-deps --release -- -D warnings
cargo fmt --check
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
