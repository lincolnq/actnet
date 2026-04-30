# Development setup

## Install Rust

Install Rust via `rustup`, the official toolchain manager:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

This installs `rustc`, `cargo`, and `rustup` into `~/.cargo/bin`. Follow the
prompts, then either restart your shell or run `source ~/.cargo/env` to add
cargo to your PATH.

The workspace uses the **stable** toolchain. `rustup` will pick up the correct
version automatically from `rust-toolchain.toml` if one is present, otherwise
it uses whatever stable version you have installed.

## System dependencies

These must be installed before building the Rust workspace.

**macOS:**
```
brew install protobuf
```

**Linux (Debian/Ubuntu):**
```
apt install protobuf-compiler
```

`protoc` is the Protocol Buffers compiler. libsignal uses it to compile `.proto`
files during its build script.

## Building

```
cargo check       # fast type-check
cargo build       # full build
cargo test        # run all tests
cargo nextest run # faster parallel test runner (cargo install cargo-nextest)
```

## Linting

```
cargo clippy
cargo audit       # check for known vulnerabilities in dependencies
```
