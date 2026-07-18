#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINDINGS="$ROOT/bpfx-ebpf/src/bindings.rs"

if [[ ! -f "$BINDINGS" ]]; then
  echo "Generating kernel bindings..."

  aya-tool generate \
    renamedata \
    dentry \
    inode \
    file \
    path \
    >"$BINDINGS"
fi
