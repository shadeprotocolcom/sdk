import { buildEddsa } from "circomlibjs";
import { getPoseidon, fieldToBigInt } from "./keys.js";
import { createDummyNoteWithTokenId, computeNullifier } from "./notes.js";
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
let eddsaInstance = null;
async function getEddsa() {
    if (!eddsaInstance) {
        eddsaInstance = await buildEddsa();
    }
    return eddsaInstance;
}
/**
 * Pad input notes array to exactly `count` entries by adding zero-value dummy notes.
 */
async function padInputNotes(inputNotes, count, keys, tokenAddress, merkleTree) {
    const padded = [...inputNotes];
    while (padded.length < count) {
        // Use the token ID directly — do NOT convert back to an address string,
        // because tokenId is a 254-bit Poseidon hash, not a 20-byte address.
        const effectiveTokenId = inputNotes.length > 0 ? inputNotes[0].token : tokenAddress;
        const dummyBase = await createDummyNoteWithTokenId(keys.masterPublicKey, effectiveTokenId);
        // Use a RANDOM dummy leafIndex in range [32768, 65535] to avoid nullifier
        // collisions across transactions. The circuit skips Merkle verification
        // for zero-value inputs, so the leaf index doesn't need to exist in the tree.
        // Using the same index (e.g. always 65535) would produce the same nullifier
        // every time, causing "nullifier already spent" on the second transaction.
        const existingIndices = padded.map((n) => n.leafIndex);
        const randomBytes = new Uint8Array(2);
        globalThis.crypto.getRandomValues(randomBytes);
        let dummyLeafIndex = 32768 + ((randomBytes[0] * 256 + randomBytes[1]) % 32768);
        while (existingIndices.includes(dummyLeafIndex)) {
            dummyLeafIndex = 32768 + ((dummyLeafIndex - 32768 + 1) % 32768);
        }
        const nullifier = await computeNullifier(keys.nullifyingKey, dummyLeafIndex);
        padded.push({
            ...dummyBase,
            leafIndex: dummyLeafIndex,
            nullifier,
            spent: false,
        });
    }
    return padded;
}
/**
 * Pad output notes to exactly `count` by creating zero-value notes for ourselves.
 */
async function padOutputNotes(outputNotes, count, keys, tokenId) {
    const padded = [...outputNotes];
    while (padded.length < count) {
        // Use the token ID directly — do NOT convert back to an address string,
        // because tokenId is a 254-bit Poseidon hash, not a 20-byte address.
        const dummyBase = await createDummyNoteWithTokenId(keys.masterPublicKey, tokenId);
        padded.push(dummyBase);
    }
    return padded;
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
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
export async function buildTransactWitness(inputNotes, outputNotes, merkleTree, keys, boundParamsHash) {
    if (inputNotes.length === 0) {
        throw new Error("At least one input note is required");
    }
    if (inputNotes.length > 2) {
        throw new Error("Maximum 2 input notes supported");
    }
    if (outputNotes.length === 0) {
        throw new Error("At least one output note is required");
    }
    if (outputNotes.length > 2) {
        throw new Error("Maximum 2 output notes supported");
    }
    const tokenId = inputNotes[0].token;
    // Verify all notes use the same token
    for (const note of inputNotes) {
        if (note.token !== tokenId) {
            throw new Error("All input notes must use the same token");
        }
    }
    for (const note of outputNotes) {
        if (note.token !== tokenId) {
            throw new Error("All output notes must use the same token");
        }
    }
    // Verify value conservation: sum(inputs) == sum(outputs)
    const inputSum = inputNotes.reduce((acc, n) => acc + n.value, 0n);
    const outputSum = outputNotes.reduce((acc, n) => acc + n.value, 0n);
    if (inputSum !== outputSum) {
        throw new Error(`Value mismatch: inputs sum to ${inputSum} but outputs sum to ${outputSum}`);
    }
    // Pad to 2x2
    const paddedInputs = await padInputNotes(inputNotes, 2, keys, tokenId, merkleTree);
    const paddedOutputs = await padOutputNotes(outputNotes, 2, keys, tokenId);
    const poseidon = await getPoseidon();
    const eddsa = await getEddsa();
    // Compute nullifiers for each input
    const nullifiers = [];
    for (const note of paddedInputs) {
        nullifiers.push(note.nullifier);
    }
    // Compute output commitments
    const commitmentsOut = paddedOutputs.map((n) => n.commitment);
    // Compute Merkle proofs
    const pathElements = [];
    const leavesIndices = [];
    for (const note of paddedInputs) {
        const proof = merkleTree.getProof(note.leafIndex);
        pathElements.push(proof.pathElements);
        // Convert path indices to leaf index bits
        leavesIndices.push(note.leafIndex);
    }
    // -- Signature --
    // Message hash = Poseidon(merkleRoot, boundParamsHash, nullifiers[0], nullifiers[1],
    //                         commitmentsOut[0], commitmentsOut[1])
    const messageHashRaw = poseidon([
        merkleTree.root,
        boundParamsHash,
        nullifiers[0],
        nullifiers[1],
        commitmentsOut[0],
        commitmentsOut[1],
    ]);
    const messageHash = fieldToBigInt(poseidon, messageHashRaw);
    // EdDSA-Poseidon sign with the spending key seed.
    // keys.spendingKey is already a raw 32-byte Uint8Array; circomlibjs
    // internally derives the signing scalar via Blake-512 + pruning.
    //
    // CRITICAL: signPoseidon expects msg as a field element in Montgomery form.
    // When poseidon() internally calls F.e(msg) on a Uint8Array, it returns
    // it as-is (assumes already in Montgomery form). So we must convert
    // messageHash to Montgomery form via F.e() before passing it.
    const msgF = eddsa.babyJub.F.e(messageHash);
    const signatureRaw = eddsa.signPoseidon(keys.spendingKey, msgF);
    // Extract R8 (point) and S (scalar) from the signature
    const sigR8x = BigInt(eddsa.F.toString(signatureRaw.R8[0]));
    const sigR8y = BigInt(eddsa.F.toString(signatureRaw.R8[1]));
    const sigS = signatureRaw.S;
    // Build witness object — all values as decimal strings
    const witness = {
        merkleRoot: merkleTree.root.toString(),
        boundParamsHash: boundParamsHash.toString(),
        nullifiers: nullifiers.map((n) => n.toString()),
        commitmentsOut: commitmentsOut.map((c) => c.toString()),
        token: tokenId.toString(),
        publicKey: [
            keys.spendingPublicKey[0].toString(),
            keys.spendingPublicKey[1].toString(),
        ],
        signature: [sigR8x.toString(), sigR8y.toString(), sigS.toString()],
        randomIn: paddedInputs.map((n) => n.random.toString()),
        valueIn: paddedInputs.map((n) => n.value.toString()),
        pathElements: pathElements.map((pe) => pe.map((e) => e.toString())),
        leavesIndices: leavesIndices.map((i) => i.toString()),
        nullifyingKey: keys.nullifyingKey.toString(),
        npkOut: paddedOutputs.map((n) => n.npk.toString()),
        valueOut: paddedOutputs.map((n) => n.value.toString()),
    };
    return witness;
}
//# sourceMappingURL=witness.js.map