import init, { ProverState } from '../pkg/arkworks_wasm.js';

export class ArkworksProver {
    static async initialize(provingKeyBytes) {
        await init();
        return new ArkworksProver(provingKeyBytes);
    }

    constructor(provingKeyBytes) {
        this.prover = new ProverState(provingKeyBytes);
    }

    async createOutputProof(noteBytes) {
        return await this.prover.create_output_proof(noteBytes);
    }
}