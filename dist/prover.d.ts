import type { WitnessInput, SnarkProof } from "./types.js";
/**
 * Error thrown when the remote prover returns a non-OK response.
 */
export declare class ProverError extends Error {
    readonly status: number;
    readonly body: string;
    constructor(message: string, status: number, body: string);
}
/**
 * Send a witness to the remote prover and return the Groth16 proof.
 *
 * The prover is expected to:
 *   1. Accept a JSON-encoded WitnessInput at `POST /prove`.
 *   2. Run the circuit witness generation + Groth16 proving.
 *   3. Return `{ proof: { a, b, c } }` where a, b, c match the Solidity
 *      verifier's calldata layout.
 *
 * @param witness   Complete witness object (all values as decimal strings).
 * @param proverUrl Base URL of the prover server (no trailing slash).
 * @returns         SnarkProof suitable for on-chain verification.
 */
export declare function generateProof(witness: WitnessInput, proverUrl: string): Promise<SnarkProof>;
//# sourceMappingURL=prover.d.ts.map