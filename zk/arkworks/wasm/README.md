# Arkworks WASM

WebAssembly bindings for Cycles's zero-knowledge proof system using Arkworks.

## Overview

This module provides WASM bindings for creating zero-knowledge proofs in Cycles, specifically focused on output proofs for shielded transactions. It uses the Arkworks library for the underlying cryptographic operations.

## Features

- Zero-knowledge output proof generation
- WASM-compatible proof serialization
- Integration with Penumbra's shielded pool
- JavaScript wrapper for easy integration
- Optimized builds with wasm-opt
- Support for both web and Node.js environments



## Structure

```
zk/arkworks/wasm/
├── build.sh              # Build script for WASM package
├── Cargo.toml           # Rust dependencies and package config
├── js/
│   └── arkworks.js      # JavaScript wrapper for easier integration
├── pkg/                 # Output directory for WASM build
└── src/
    ├── lib.rs          # Main WASM bindings and ProverState
    ├── nullifier/      # Nullifier-related functionality
    └── output/
        └── proof.rs    # Output proof circuit implementation
```

## Quick start
### Prerequisites

- Rust toolchain
- wasm-pack (`cargo install wasm-pack`)
- wasm-opt (optional, for optimized builds)

### Building

You can use the provided build script:

```bash
# Build for web (default)
./build.sh

# Build for React Native
./build.sh --target react-native

# Build optimized version
./build.sh --target react-native --release
```

## Usage

### JavaScript/TypeScript

Using the wrapper:
```javascript
import { ArkworksProver } from '@penumbra/arkworks-wasm/js/arkworks';

async function createProof(noteBytes, provingKeyBytes) {
    // Initialize the prover
    const prover = await ArkworksProver.initialize(provingKeyBytes);
    
    // Generate a proof
    const proofBytes = await prover.createOutputProof(noteBytes);
    return proofBytes;
}
```

Using the raw WASM bindings:
```javascript
import init, { ProverState } from '@penumbra/arkworks-wasm';

async function createProof(noteBytes, provingKeyBytes) {
    // Initialize the WASM module
    await init();
    
    // Create a new prover with the proving key
    const prover = new ProverState(provingKeyBytes);
    
    // Generate a proof
    const proofBytes = await prover.create_output_proof(noteBytes);
    return proofBytes;
}
```

### Rust

```rust
use arkworks_wasm::{ProverState, OutputProof};

fn create_proof(note_bytes: &[u8], proving_key: ProvingKey<Bls12_377>) -> Vec<u8> {
    let prover = ProverState { proving_key };
    prover.create_output_proof(note_bytes)
}
```


## Dependencies

### Rust Dependencies
- `ark-groth16` - Groth16 proof system implementation
- `decaf377` - Decaf377 curve operations
- `wasm-bindgen` - WASM binding generation
- `penumbra-shielded-pool` - Shielded pool functionality
- `ark-serialize` - Serialization for cryptographic types
- `ark-ff` - Finite field operations
- `ark-relations` - Constraint system definitions

### Build Dependencies
- `wasm-pack` - Build tooling
- `wasm-opt` - (Optional) WebAssembly optimizer

### JavaScript Dependencies
None required - the package is self-contained with the generated WASM module

## Build Output

After running the build script, the following files will be generated in the `pkg/` directory:

```
pkg/
├── arkworks_wasm_bg.wasm      # Raw WASM binary
├── arkworks_wasm_bg.wasm.d.ts # TypeScript definitions
├── arkworks_wasm.d.ts         # TypeScript definitions
├── arkworks_wasm.js           # JavaScript bindings
└── package.json               # NPM package configuration
```

## License

Same as Penumbra

