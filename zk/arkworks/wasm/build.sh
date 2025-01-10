#!/bin/bash
set -e

# Install Binaryen via npm
npm install binaryen

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
mkdir -p pkg/js

case "$TARGET" in
    "web")
        echo "Building for web..."
        wasm-pack build --target web --out-dir pkg/web
        if [ "$RELEASE" = "1" ]; then
            node --input-type=module -e "
                import binaryen from 'binaryen';
                import { readFileSync, writeFileSync } from 'fs';
                const wasmBuffer = readFileSync('pkg/web/arkworks_wasm_bg.wasm');
                const module = binaryen.readBinary(wasmBuffer);
                module.optimize();
                writeFileSync('pkg/web/arkworks_wasm_bg_opt.wasm', module.emitBinary());
                module.dispose();
            "
        fi
        ;;
        
    "react-native")
        
        echo "Building for React Native..."
        # Build wasm module
        wasm-pack build --target bundler --out-dir pkg/native
        
        # Convert to JavaScript using Binaryen
        node --input-type=module -e "
            import binaryen from 'binaryen';
            import { readFileSync, writeFileSync } from 'fs';
            const wasmBuffer = readFileSync('pkg/native/arkworks_wasm_bg.wasm');
            const module = binaryen.readBinary(wasmBuffer);
            const jsCode = module.emitAsmjs();
            writeFileSync('pkg/js/arkworks_wasm2js.js', jsCode);
            module.dispose();
        "
        
        # Copy WASM file to js directory
        cp pkg/native/arkworks_wasm_bg.wasm pkg/js/
        
        # Create initialization wrapper
        cat > pkg/js/init.js << EOL
import { WebAssembly } from 'react-native-webassembly';
import wasmBinary from './arkworks_wasm_bg.wasm';

export async function initializeWasm() {
    const instance = await WebAssembly.instantiate(wasmBinary, {
        env: {
            memory: new WebAssembly.Memory({ initial: 256 }),
        }
    });
    return instance.exports;
}
EOL
        
        # Create index file
        cat > pkg/js/index.js << EOL
import { initializeWasm } from './init';

export class ArkworksProver {
    static async initialize(provingKeyBytes) {
        const exports = await initializeWasm();
        return new ArkworksProver(exports);
    }

    constructor(wasmExports) {
        this.exports = wasmExports;
    }

    async createOutputProof(noteBytes) {
        return this.exports.create_output_proof(noteBytes);
    }
}
EOL
        ;;
        
    *)
        echo "Unknown target: $TARGET"
        echo "Available targets: web, react-native"
        exit 1
        ;;
esac

echo "Build completed for target: $TARGET"