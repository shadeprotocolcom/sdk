import { type OwnedNote, type Note, type MerkleTree, type ShadeKeys, type WitnessInput } from "./types.js";
/**
 * Build the witness (private + public inputs) for a 2-input / 2-output
 * transact circuit.
 *
 * This handles:
 * - Padding inputs/outputs with dummy zero-value notes when fewer than 2 are provided.
 * - Computing Merkle proofs for each input note.
 * - Computing the EdDSA-Poseidon signature over the hash of all public inputs.
 *
 * @param inputNotes      1 or 2 owned notes to spend.
 * @param outputNotes     1 or 2 output notes to create.
 * @param merkleTree      Current commitment Merkle tree.
 * @param keys            Spender's full key set.
 * @param boundParamsHash Hash of the bound parameters (adaptID, chainID, fees, …).
 * @returns               WitnessInput ready for the prover.
 */
export declare function buildTransactWitness(inputNotes: OwnedNote[], outputNotes: Note[], merkleTree: MerkleTree, keys: ShadeKeys, boundParamsHash: bigint): Promise<WitnessInput>;
//# sourceMappingURL=witness.d.ts.map