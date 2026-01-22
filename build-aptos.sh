#!/bin/bash
set -e

# Copy Aptos-specific Cargo.toml
cp Cargo-aptos.toml Cargo.toml

# Copy over Cargo.lock from aptos-core to ensure dependency consistency
cp aptos-core/Cargo.lock Cargo.lock


# Build with Aptos features
cargo build --release --features aptos
