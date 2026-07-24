#!/usr/bin/bash

RUSTFLAGS=-Awarnings cargo +nightly build \
  -Z build-std=core \
  --target bpfel-unknown-none \
  --release \
  --manifest-path bpfx-ebpf/Cargo.toml

cp target/bpfel-unknown-none/release/bpfx-ebpf assets/bpfx-ebpf.o

RUST_LOG=INFO cargo +nightly run --config 'target."cfg(all())".runner="sudo -E"'
