import { buildPoseidon, buildBabyjub, buildEddsa } from "circomlibjs";
import { type ShadeKeys } from "./types.js";
export declare function getPoseidon(): Promise<Awaited<ReturnType<typeof buildPoseidon>>>;
export declare function getBabyjub(): Promise<Awaited<ReturnType<typeof buildBabyjub>>>;
export declare function getEddsa(): Promise<Awaited<ReturnType<typeof buildEddsa>>>;
/**
 * Convert a circomlibjs field element (Uint8Array in LE / F1Field) to bigint.
 */
export declare function fieldToBigInt(poseidon: Awaited<ReturnType<typeof buildPoseidon>>, element: unknown): bigint;
/**
 * Derive the full Shade key set from a wallet signature over the canonical
 * key-derivation message.
 *
 * @param signature  Hex-encoded ECDSA signature (with or without 0x prefix).
 */
export declare function deriveShadeKeys(signature: string): Promise<ShadeKeys>;
/**
 * Generate a note public key (stealth address component).
 *
 * @param masterPublicKey  Receiver's master public key.
 * @param random           Random blinding scalar chosen by the sender.
 */
export declare function generateNotePublicKey(masterPublicKey: bigint, random: bigint): Promise<bigint>;
//# sourceMappingURL=keys.d.ts.map