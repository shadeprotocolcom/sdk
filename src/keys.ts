import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes, concatBytes } from "@noble/hashes/utils";
// circomlibjs provides Poseidon, BabyJubjub, and EdDSA at runtime
import { buildPoseidon, buildBabyjub, buildEddsa } from "circomlibjs";
import {
  VIEWING_KEY_DOMAIN,
  type ShadeKeys,
} from "./types.js";

// ---------------------------------------------------------------------------
// Singleton initialisers (circomlibjs is async)
// ---------------------------------------------------------------------------

let poseidonInstance: Awaited<ReturnType<typeof buildPoseidon>> | null = null;
let babyjubInstance: Awaited<ReturnType<typeof buildBabyjub>> | null = null;
let eddsaInstance: Awaited<ReturnType<typeof buildEddsa>> | null = null;

export async function getPoseidon(): Promise<
  Awaited<ReturnType<typeof buildPoseidon>>
> {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

export async function getBabyjub(): Promise<
  Awaited<ReturnType<typeof buildBabyjub>>
> {
  if (!babyjubInstance) {
    babyjubInstance = await buildBabyjub();
  }
  return babyjubInstance;
}

export async function getEddsa(): Promise<
  Awaited<ReturnType<typeof buildEddsa>>
> {
  if (!eddsaInstance) {
    eddsaInstance = await buildEddsa();
  }
  return eddsaInstance;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert a hex string (with or without 0x prefix) to a Uint8Array.
 */
function hexToBytes(hex: string): Uint8Array {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (cleaned.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to a bigint (big-endian).
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

/**
 * Convert a circomlibjs field element (Uint8Array in LE / F1Field) to bigint.
 */
export function fieldToBigInt(
  poseidon: Awaited<ReturnType<typeof buildPoseidon>>,
  element: unknown,
): bigint {
  return BigInt(poseidon.F.toString(element));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Derive the full Shade key set from a wallet signature over the canonical
 * key-derivation message.
 *
 * @param signature  Hex-encoded ECDSA signature (with or without 0x prefix).
 */
export async function deriveShadeKeys(signature: string): Promise<ShadeKeys> {
  const poseidon = await getPoseidon();
  const eddsa = await getEddsa();

  const sigBytes = hexToBytes(signature);

  // --- Spending key (raw seed) ---
  // SHA-256 of the raw signature bytes produces a 32-byte seed.
  // This seed is passed directly to circomlibjs EdDSA functions which
  // internally derive the actual signing scalar via Blake-512 + pruning.
  const spendingKey = sha256(sigBytes);

  // --- Spending public key ---
  // Use circomlibjs EdDSA's native key derivation so that the public key
  // is consistent with what signPoseidon() uses internally:
  //   blake512(seed) -> prune -> scalar -> (scalar >> 3) * Base8
  const spendingPubRaw = eddsa.prv2pub(spendingKey);
  const spendingPublicKey: [bigint, bigint] = [
    BigInt(eddsa.F.toString(spendingPubRaw[0])),
    BigInt(eddsa.F.toString(spendingPubRaw[1])),
  ];

  // --- Viewing key ---
  // Distinct domain-separated derivation: SHA-256(signature || domain tag).
  const viewingKey = sha256(
    concatBytes(sigBytes, utf8ToBytes(VIEWING_KEY_DOMAIN)),
  );

  // --- Nullifying key ---
  // Poseidon hash of the spending key seed interpreted as a big-endian bigint.
  const spendingKeySeedInt = bytesToBigInt(spendingKey);
  const nullifyingKeyRaw = poseidon([spendingKeySeedInt]);
  const nullifyingKey = fieldToBigInt(poseidon, nullifyingKeyRaw);

  // --- Master public key ---
  // Poseidon(spendingPubKey.x, spendingPubKey.y, nullifyingKey)
  const masterPublicKeyRaw = poseidon([
    spendingPublicKey[0],
    spendingPublicKey[1],
    nullifyingKey,
  ]);
  const masterPublicKey = fieldToBigInt(poseidon, masterPublicKeyRaw);

  return {
    spendingKey,
    spendingPublicKey,
    viewingKey,
    nullifyingKey,
    masterPublicKey,
  };
}

/**
 * Generate a note public key (stealth address component).
 *
 * @param masterPublicKey  Receiver's master public key.
 * @param random           Random blinding scalar chosen by the sender.
 */
export async function generateNotePublicKey(
  masterPublicKey: bigint,
  random: bigint,
): Promise<bigint> {
  const poseidon = await getPoseidon();
  const raw = poseidon([masterPublicKey, random]);
  return fieldToBigInt(poseidon, raw);
}
