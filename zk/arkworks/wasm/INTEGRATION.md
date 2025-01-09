# Integrating Arkworks WASM with React Native / Expo 📱

This guide explains how to integrate the Arkworks WASM zero-knowledge proof system into your React Native or Expo application.

## Prerequisites 📋

- React Native project or Expo project
- Node.js and npm/yarn
- Basic understanding of zero-knowledge proofs

## Installation 🛠️

1. Install the required dependencies:

```bash
# For React Native
npm install react-native-webassembly react-native-get-random-values

# For Expo
expo install react-native-webassembly react-native-get-random-values
```

2. Build the WASM package for React Native:

```bash
cd path/to/arkworks-wasm
./build.sh --target react-native --release
```

3. Copy the built package to your project:

```bash
cp -r pkg/native/ ../your-react-native-app/assets/arkworks-wasm/
```

## Integration Steps 🔧

### 1. Initialize WebAssembly Environment

Create a new file `arkworks-setup.ts`:

```typescript
import { WebAssembly } from 'react-native-webassembly';
import 'react-native-get-random-values';

// Ensure WebAssembly is initialized before using
export const initializeWasm = async () => {
  if (typeof WebAssembly === 'undefined') {
    throw new Error('WebAssembly is not supported');
  }
};
```

### 2. Create Arkworks Wrapper

Create `arkworks.ts`:

```typescript
import { ArkworksProver } from '../assets/arkworks-wasm';

export class ZKProver {
  private static instance: ArkworksProver | null = null;

  static async initialize(provingKeyBytes: Uint8Array): Promise<ZKProver> {
    if (!this.instance) {
      await initializeWasm();
      this.instance = await ArkworksProver.initialize(provingKeyBytes);
    }
    return new ZKProver();
  }

  async createProof(noteBytes: Uint8Array): Promise<Uint8Array> {
    if (!ZKProver.instance) {
      throw new Error('ZKProver not initialized');
    }
    return await ZKProver.instance.createOutputProof(noteBytes);
  }
}
```

### 3. Usage in React Native Components

```typescript
import { ZKProver } from './arkworks';

const YourComponent = () => {
  const [prover, setProver] = useState<ZKProver | null>(null);

  useEffect(() => {
    const init = async () => {
      // Load your proving key here
      const provingKey = await loadProvingKey();
      const zkProver = await ZKProver.initialize(provingKey);
      setProver(zkProver);
    };
    init();
  }, []);

  const generateProof = async () => {
    if (!prover) return;
    
    try {
      const noteBytes = new Uint8Array([/* your note data */]);
      const proof = await prover.createProof(noteBytes);
      console.log('Proof generated:', proof);
    } catch (error) {
      console.error('Failed to generate proof:', error);
    }
  };

  return (
    <Button 
      title="Generate Proof" 
      onPress={generateProof}
      disabled={!prover} 
    />
  );
};
```

## Configuration 🔧

### Metro Config (React Native)

Update `metro.config.js`:

```javascript
module.exports = {
  resolver: {
    assetExts: ['wasm'],
  },
};
```

### Expo Config

Update `app.json`:

```json
{
  "expo": {
    "plugins": [
      [
        "react-native-webassembly",
        {
          "enableWasmFiles": true
        }
      ]
    ]
  }
}
```

## Performance Considerations ⚡

1. Initialize the prover during app startup
2. Cache the proving key
3. Use the release build of the WASM package
4. Consider using Web Workers for heavy computations

## Troubleshooting 🔍

Common issues and solutions:

1. **WASM not found**: Ensure the WASM file is properly bundled in assets
2. **Memory errors**: Increase WASM memory limit in build configuration
3. **Performance issues**: Use the release build with optimizations

## Example Project Structure 📁

```
your-react-native-app/
├── assets/
│   └── arkworks-wasm/
│       ├── arkworks_wasm_bg.wasm
│       └── index.js
├── src/
│   ├── arkworks-setup.ts
│   ├── arkworks.ts
│   └── components/
│       └── ZKProofGenerator.tsx
└── metro.config.js
```

## References 📚

- Build script documentation: [build.sh](startLine: 1, endLine: 55)
- JavaScript wrapper: [arkworks.js](startLine: 1, endLine: 16)
- WASM implementation: [lib.rs](startLine: 1, endLine: 62)
