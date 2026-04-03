import { type Note, type OwnedNote } from "./types.js";
/**
 * Compute the Poseidon commitment for a note.
 *
 * commitment = Poseidon(npk, tokenId, value)
 */
export declare function computeCommitment(npk: bigint, tokenId: bigint, value: bigint): Promise<bigint>;
/**
 * Compute the nullifier that marks a note as spent.
 *
 * nullifier = Poseidon(nullifyingKey, leafIndex)
 */
export declare function computeNullifier(nullifyingKey: bigint, leafIndex: number): Promise<bigint>;
/**
 * Derive a canonical token ID from an ERC-20 address.
 *
 * tokenId = keccak256(tokenType=0 || address || subID=0) mod SNARK_FIELD
 *
 * The encoding matches the Solidity side: abi.encodePacked(uint8, address, uint256).
 */
export declare function computeTokenId(tokenAddress: string): bigint;
/**
 * Create a new note destined for a receiver identified by their master public key.
 *
 * @param masterPublicKey  Receiver's master public key.
 * @param tokenAddress     ERC-20 token address (e.g. wCBTC).
 * @param value            Token amount in the smallest unit.
 * @returns                A fully populated Note.
 */
export declare function createNote(masterPublicKey: bigint, tokenAddress: string, value: bigint): Promise<Note>;
/**
 * Create a note with a specific random value (used when the sender already
 * chose the randomness, e.g. during decryption round-trips or tests).
 */
export declare function createNoteWithRandom(masterPublicKey: bigint, tokenAddress: string, value: bigint, random: bigint): Promise<Note>;
/**
 * Annotate a Note with ownership metadata, turning it into an OwnedNote.
 */
export declare function toOwnedNote(note: Note, leafIndex: number, nullifyingKey: bigint): Promise<OwnedNote>;
/**
 * Create a dummy (zero-value) note used for circuit padding.
 */
export declare function createDummyNote(masterPublicKey: bigint, tokenAddress: string): Promise<Note>;
/**
 * Create a dummy (zero-value) note using an already-computed token ID.
 *
 * Unlike `createDummyNote` which takes a token address and calls `computeTokenId`,
 * this function accepts the token ID directly. This avoids the bug where a 254-bit
 * Poseidon hash is formatted as a 40-char hex string and fed back into
 * `computeTokenId`, which expects a 20-byte Ethereum address.
 */
export declare function createDummyNoteWithTokenId(masterPublicKey: bigint, tokenId: bigint): Promise<Note>;
//# sourceMappingURL=notes.d.ts.map