#!/bin/bash
set -e

# Install required tools if not present
which wasm-pack || cargo install wasm-pack
which wasm-opt || npm install -g wasm-opt

# Default target
TARGET="web"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --target) TARGET="$2"; shift ;;
        --release) RELEASE=1 ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Create output directories
mkdir -p pkg/web
mkdir -p pkg/native

case $TARGET in
    "web")
        echo "Building for web..."
        wasm-pack build --target web --out-dir pkg/web
        if [ "$RELEASE" = "1" ]; then
            wasm-opt -O4 -o pkg/web/arkworks_wasm_bg_opt.wasm pkg/web/arkworks_wasm_bg.wasm
        fi
        ;;
        
    "react-native")
        echo "Building for React Native..."
        # Build with no-modules target for React Native compatibility
        wasm-pack build --target bundler --out-dir pkg/native
        if [ "$RELEASE" = "1" ]; then
            wasm-opt -O4 -o pkg/native/arkworks_wasm_bg_opt.wasm pkg/native/arkworks_wasm_bg.wasm
        fi
        # Generate React Native specific bindings
        cat > pkg/native/index.js << EOL
const { NativeModules } = require('react-native');
module.exports = require('./arkworks_wasm.js');
EOL
        ;;
        
    *)
        echo "Unknown target: $TARGET"
        echo "Available targets: web, react-native"
        exit 1
        ;;
esac

echo "Build completed for target: $TARGET"