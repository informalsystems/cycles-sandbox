#!/bin/bash
set -e

# Install wasm-pack if not already installed
which wasm-pack || cargo install wasm-pack

# Build the wasm package
wasm-pack build --target web --out-dir pkg

# Optional: Create an optimized build
if [ "$1" = "--release" ]; then
    wasm-opt -O4 -o pkg/arkworks_wasm_bg_opt.wasm pkg/arkworks_wasm_bg.wasm
fi