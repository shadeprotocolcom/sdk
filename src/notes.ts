import { keccak_256 } from "@noble/hashes/sha3";
import { getPoseidon, generateNotePublicKey, fieldToBigInt } from "./keys.js";
import { SNARK_FIELD, type Note, type OwnedNote } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Encode a 20-byte Ethereum address into a left-padded 32-byte buffer.
 */
function addressToBytes32(address: string): Uint8Array {
  const cleaned = address.startsWith("0x") ? address.slice(2) : address;
  if (cleaned.length !== 40) {
    throw new Error(`Invalid address length: expected 40 hex chars, got ${cleaned.length}`);
  }
  const buf = new Uint8Array(32);
  for (let i = 0; i < 20; i++) {
    buf[12 + i] = parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
  }
  return buf;
}

/**
 * Write a uint256 as a big-endian 32-byte buffer.
 */
function uint256ToBytes32(value: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

/**
 * Generate a cryptographically secure random bigint in [0, SNARK_FIELD).
 */
function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) + BigInt(b);
  }
  return value % SNARK_FIELD;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute the Poseidon commitment for a note.
 *
 * commitment = Poseidon(npk, tokenId, value)
 */
export async function computeCommitment(
  npk: bigint,
  tokenId: bigint,
  value: bigint,
): Promise<bigint> {
  const poseidon = await getPoseidon();
  const raw = poseidon([npk, tokenId, value]);
  return fieldToBigInt(poseidon, raw);
}

/**
 * Compute the nullifier that marks a note as spent.
 *
 * nullifier = Poseidon(nullifyingKey, leafIndex)
 */
export async function computeNullifier(
  nullifyingKey: bigint,
  leafIndex: number,
): Promise<bigint> {
  const poseidon = await getPoseidon();
  const raw = poseidon([nullifyingKey, BigInt(leafIndex)]);
  return fieldToBigInt(poseidon, raw);
}

/**
 * Derive a canonical token ID from an ERC-20 address.
 *
 * tokenId = keccak256(tokenType=0 || address || subID=0) mod SNARK_FIELD
 *
 * The encoding matches the Solidity side: abi.encodePacked(uint8, address, uint256).
 */
export function computeTokenId(tokenAddress: string): bigint {
  // tokenType (1 byte, 0x00) || address (20 bytes, left-padded to 32) || subID (32 bytes, 0)
  // We use a tighter packing: uint8 (1 byte) + address (20 bytes) + uint256 (32 bytes) = 53 bytes
  const tokenTypeBuf = new Uint8Array([0x00]);
  const addressBuf = addressToBytes32(tokenAddress).slice(12); // raw 20 bytes
  const subIdBuf = uint256ToBytes32(0n);

  const packed = new Uint8Array(1 + 20 + 32);
  packed.set(tokenTypeBuf, 0);
  packed.set(addressBuf, 1);
  packed.set(subIdBuf, 21);

  const hash = keccak_256(packed);

  let value = 0n;
  for (const b of hash) {
    value = (value << 8n) + BigInt(b);
  }

  return value % SNARK_FIELD;
}

/**
 * Create a new note destined for a receiver identified by their master public key.
 *
 * @param masterPublicKey  Receiver's master public key.
 * @param tokenAddress     ERC-20 token address (e.g. wCBTC).
 * @param value            Token amount in the smallest unit.
 * @returns                A fully populated Note.
 */
export async function createNote(
  masterPublicKey: bigint,
  tokenAddress: string,
  value: bigint,
): Promise<Note> {
  const random = randomFieldElement();
  const npk = await generateNotePublicKey(masterPublicKey, random);
  const token = computeTokenId(tokenAddress);
  const commitment = await computeCommitment(npk, token, value);

  return { npk, random, token, value, commitment };
}

/**
 * Create a note with a specific random value (used when the sender already
 * chose the randomness, e.g. during decryption round-trips or tests).
 */
export async function createNoteWithRandom(
  masterPublicKey: bigint,
  tokenAddress: string,
  value: bigint,
  random: bigint,
): Promise<Note> {
  const npk = await generateNotePublicKey(masterPublicKey, random);
  const token = computeTokenId(tokenAddress);
  const commitment = await computeCommitment(npk, token, value);

  return { npk, random, token, value, commitment };
}

/**
 * Annotate a Note with ownership metadata, turning it into an OwnedNote.
 */
export async function toOwnedNote(
  note: Note,
  leafIndex: number,
  nullifyingKey: bigint,
): Promise<OwnedNote> {
  const nullifier = await computeNullifier(nullifyingKey, leafIndex);
  return {
    ...note,
    leafIndex,
    nullifier,
    spent: false,
  };
}

/**
 * Create a dummy (zero-value) note used for circuit padding.
 */
export async function createDummyNote(
  masterPublicKey: bigint,
  tokenAddress: string,
): Promise<Note> {
  return createNote(masterPublicKey, tokenAddress, 0n);
}

/**
 * Create a dummy (zero-value) note using an already-computed token ID.
 *
 * Unlike `createDummyNote` which takes a token address and calls `computeTokenId`,
 * this function accepts the token ID directly. This avoids the bug where a 254-bit
 * Poseidon hash is formatted as a 40-char hex string and fed back into
 * `computeTokenId`, which expects a 20-byte Ethereum address.
 */
export async function createDummyNoteWithTokenId(
  masterPublicKey: bigint,
  tokenId: bigint,
): Promise<Note> {
  const random = randomFieldElement();
  const npk = await generateNotePublicKey(masterPublicKey, random);
  const commitment = await computeCommitment(npk, tokenId, 0n);

  return { npk, random, token: tokenId, value: 0n, commitment };
}
