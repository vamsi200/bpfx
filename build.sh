#!/usr/bin/env bash
set -e

aya-tool generate \
  renamedata \
  dentry \
  inode \
  file \
  path \
  >bpfx-ebpf/src/bindings.rs

RUSTFLAGS=-Awarnings cargo +nightly build \
  -Z build-std=core \
  --target bpfel-unknown-none \
  --release \
  --manifest-path bpfx-ebpf/Cargo.toml

mkdir -p assets
cp target/bpfel-unknown-none/release/bpfx-ebpf assets/bpfx-ebpf.o
