#!/bin/bash
set -e

# Copy Aptos-specific Cargo.toml
cp Cargo-aptos.toml Cargo.toml

# Copy over Cargo.lock from aptos-core to ensure dependency consistency
cp aptos-core/Cargo.lock Cargo.lock

# Copy cargo config to enable tokio_unstable flag (required for disable_lifo_slot)
mkdir -p .cargo
cp aptos-core/.cargo/config.toml .cargo/config.toml

# Build with Aptos features
cargo build --release --features aptos
