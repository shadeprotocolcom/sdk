import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";
import { getBabyjub } from "./keys.js";
import {
  SNARK_FIELD,
  type Note,
  type ShieldCiphertext,
  type CommitmentCiphertext,
  type OnChainShieldCiphertext,
  type OnChainTransactCiphertext,
} from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Encode a bigint as a big-endian 32-byte buffer.
 */
function bigIntToBytes32(value: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

/**
 * Decode a big-endian byte buffer into a bigint.
 */
function bytes32ToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) + BigInt(b);
  }
  return value;
}

/**
 * Convert a hex string to Uint8Array.
 */
function hexToBytes(hex: string): Uint8Array {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Generate a random scalar in [1, SNARK_FIELD).
 */
function randomScalar(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let v = 0n;
  for (const b of bytes) {
    v = (v << 8n) + BigInt(b);
  }
  // Ensure non-zero and within field
  return (v % (SNARK_FIELD - 1n)) + 1n;
}

/**
 * Derive a symmetric key from a BabyJubjub shared secret point.
 *
 * We SHA-256 the concatenation of the x and y coordinates.
 */
function deriveSymmetricKey(sharedPoint: [bigint, bigint]): Uint8Array {
  const xBytes = bigIntToBytes32(sharedPoint[0]);
  const yBytes = bigIntToBytes32(sharedPoint[1]);
  return sha256(concatBytes(xBytes, yBytes));
}

/**
 * Serialise note fields into a plaintext buffer:
 *   npk (32) || token (32) || value (32) || random (32) = 128 bytes
 */
function serialiseNote(note: Note): Uint8Array {
  return concatBytes(
    bigIntToBytes32(note.npk),
    bigIntToBytes32(note.token),
    bigIntToBytes32(note.value),
    bigIntToBytes32(note.random),
  );
}

/**
 * Deserialise a 128-byte plaintext back into partial note fields.
 */
function deserialiseNote(
  plaintext: Uint8Array,
): { npk: bigint; token: bigint; value: bigint; random: bigint } {
  if (plaintext.length !== 128) {
    throw new Error(`Invalid plaintext length: expected 128, got ${plaintext.length}`);
  }
  return {
    npk: bytes32ToBigInt(plaintext.slice(0, 32)),
    token: bytes32ToBigInt(plaintext.slice(32, 64)),
    value: bytes32ToBigInt(plaintext.slice(64, 96)),
    random: bytes32ToBigInt(plaintext.slice(96, 128)),
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt a note so that only the holder of `receiverViewingKey` can decrypt.
 *
 * Performs ECDH on BabyJubjub between an ephemeral key pair and the receiver's
 * viewing public key, then encrypts with XChaCha20-Poly1305.
 *
 * @param note                   The note to encrypt.
 * @param senderRandom           Additional randomness (mixed into nonce generation).
 * @param receiverViewingPubKey  The receiver's viewing public key, encoded as
 *                               two 32-byte big-endian coordinates concatenated (64 bytes).
 */
export async function encryptNote(
  note: Note,
  senderRandom: bigint,
  receiverViewingPubKey: Uint8Array,
): Promise<ShieldCiphertext> {
  const babyjub = await getBabyjub();

  // Decode receiver viewing public key (64 bytes → two field elements)
  if (receiverViewingPubKey.length !== 64) {
    throw new Error(
      `receiverViewingPubKey must be 64 bytes, got ${receiverViewingPubKey.length}`,
    );
  }
  const recvPubX = bytes32ToBigInt(receiverViewingPubKey.slice(0, 32));
  const recvPubY = bytes32ToBigInt(receiverViewingPubKey.slice(32, 64));
  const recvPubPoint = [babyjub.F.e(recvPubX), babyjub.F.e(recvPubY)];

  // Generate ephemeral key pair
  const ephemeralSecret = randomScalar();
  const ephemeralPubRaw = babyjub.mulPointEscalar(babyjub.Base8, ephemeralSecret);
  const ephemeralPubKey: [bigint, bigint] = [
    BigInt(babyjub.F.toString(ephemeralPubRaw[0])),
    BigInt(babyjub.F.toString(ephemeralPubRaw[1])),
  ];

  // ECDH: shared = ephemeralSecret * receiverPub
  const sharedRaw = babyjub.mulPointEscalar(recvPubPoint, ephemeralSecret);
  const sharedPoint: [bigint, bigint] = [
    BigInt(babyjub.F.toString(sharedRaw[0])),
    BigInt(babyjub.F.toString(sharedRaw[1])),
  ];

  // Derive symmetric key
  const symmetricKey = deriveSymmetricKey(sharedPoint);

  // Nonce: first 24 bytes of SHA-256(senderRandom || ephemeralPub.x)
  const nonceSource = sha256(
    concatBytes(bigIntToBytes32(senderRandom), bigIntToBytes32(ephemeralPubKey[0])),
  );
  const nonce = nonceSource.slice(0, 24);

  // Encrypt
  const plaintext = serialiseNote(note);
  const cipher = xchacha20poly1305(symmetricKey, nonce);
  const data = cipher.encrypt(plaintext);

  return { ephemeralPubKey, nonce, data };
}

/**
 * Attempt to decrypt a commitment ciphertext using the local viewing key.
 *
 * @param ciphertext   On-chain ciphertext (hex-encoded fields).
 * @param viewingKey   32-byte viewing private key (the SHA-256 derived secret).
 * @returns            The decrypted Note, or null if decryption fails (not ours).
 */
export async function decryptNote(
  ciphertext: CommitmentCiphertext,
  viewingKey: Uint8Array,
): Promise<Note | null> {
  const babyjub = await getBabyjub();

  try {
    // Parse ephemeral public key
    const epX = BigInt(ciphertext.ephemeralPubKey[0]);
    const epY = BigInt(ciphertext.ephemeralPubKey[1]);
    const ephPubPoint = [babyjub.F.e(epX), babyjub.F.e(epY)];

    // Derive the viewing private scalar from the 32-byte key
    let viewingScalar = 0n;
    for (const b of viewingKey) {
      viewingScalar = (viewingScalar << 8n) + BigInt(b);
    }
    viewingScalar = viewingScalar % SNARK_FIELD;

    // ECDH: shared = viewingScalar * ephemeralPub
    const sharedRaw = babyjub.mulPointEscalar(ephPubPoint, viewingScalar);
    const sharedPoint: [bigint, bigint] = [
      BigInt(babyjub.F.toString(sharedRaw[0])),
      BigInt(babyjub.F.toString(sharedRaw[1])),
    ];

    // Derive symmetric key
    const symmetricKey = deriveSymmetricKey(sharedPoint);

    // Parse nonce and data
    const nonce = hexToBytes(ciphertext.nonce);
    const data = hexToBytes(ciphertext.data);

    if (nonce.length !== 24) {
      return null;
    }

    // Decrypt
    const cipher = xchacha20poly1305(symmetricKey, nonce);
    const plaintext = cipher.decrypt(data);

    // Deserialise
    const fields = deserialiseNote(plaintext);

    // Reconstruct commitment
    const { computeCommitment } = await import("./notes.js");
    const commitment = await computeCommitment(fields.npk, fields.token, fields.value);

    return {
      npk: fields.npk,
      random: fields.random,
      token: fields.token,
      value: fields.value,
      commitment,
    };
  } catch {
    // Decryption failure means this ciphertext is not addressed to us.
    return null;
  }
}

/**
 * Compute the viewing public key from a viewing private key.
 *
 * viewingPub = viewingScalar * G (BabyJubjub base point)
 *
 * Returns 64 bytes: x (32 BE) || y (32 BE).
 */
export async function viewingPublicKey(
  viewingKey: Uint8Array,
): Promise<Uint8Array> {
  const babyjub = await getBabyjub();

  let scalar = 0n;
  for (const b of viewingKey) {
    scalar = (scalar << 8n) + BigInt(b);
  }
  scalar = scalar % SNARK_FIELD;

  const pubRaw = babyjub.mulPointEscalar(babyjub.Base8, scalar);
  const x = BigInt(babyjub.F.toString(pubRaw[0]));
  const y = BigInt(babyjub.F.toString(pubRaw[1]));

  return concatBytes(bigIntToBytes32(x), bigIntToBytes32(y));
}

// ---------------------------------------------------------------------------
// On-chain format decryption
// ---------------------------------------------------------------------------

/**
 * Convert a hex string to a Uint8Array, handling "0x" prefix.
 */
function hexToBytesStrict(hex: string): Uint8Array {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (cleaned.length === 0) return new Uint8Array(0);
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to a hex string with "0x" prefix.
 */
function bytesToHexStr(bytes: Uint8Array): string {
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

/**
 * Decrypt a Shield event ciphertext.
 *
 * On-chain Shield format:
 *   encryptedBundle[3] = first 96 bytes of encrypted data (3 x bytes32)
 *   shieldKey = ephemeral public key x-coordinate
 *
 * The encrypted data from encryptNote() is 144 bytes (128 plaintext + 16 tag).
 * Only the first 96 bytes are stored in encryptedBundle. The remaining 48 bytes
 * (data[96:128] + tag[0:16]) and the nonce are NOT stored on-chain for shield
 * events, so shield ciphertexts can only be decrypted by the shielder who knows
 * the full original ciphertext. For shield events, the preimage is also emitted
 * in plaintext, so we reconstruct the note directly from the preimage.
 *
 * However, if the indexer provides the full preimage data, we can try to
 * use the shieldKey to perform ECDH. Since shield events also emit the
 * CommitmentPreimage in cleartext, this function returns null (the sync logic
 * should use the preimage directly for Shield events).
 */
export async function decryptShieldCiphertext(
  _ct: OnChainShieldCiphertext,
  _viewingKey: Uint8Array,
): Promise<Note | null> {
  // Shield events do not store enough ciphertext data for decryption.
  // The encrypted bundle only contains 96 of 144 bytes, and the nonce
  // is not stored. Shield events emit the CommitmentPreimage in cleartext,
  // so the sync logic should reconstruct the note from the preimage directly.
  return null;
}

/**
 * Decrypt a Transact event ciphertext.
 *
 * On-chain Transact format (from buildCommitmentCiphertexts in client.ts):
 *   ciphertext[4] = first 128 bytes of encrypted data (4 x bytes32)
 *   blindedSenderViewingKey = ephemeral public key x-coordinate
 *   blindedReceiverViewingKey = ephemeral public key y-coordinate
 *   annotationData = Poly1305 tag (16 bytes) + XChaCha20 nonce (24 bytes)
 *   memo = unused
 *
 * To decrypt, we reverse the packing:
 *   ephemeralPubKey = [blindedSenderViewingKey, blindedReceiverViewingKey]
 *   nonce = annotationData[16:40]  (last 24 bytes)
 *   data = ciphertext[0:128] + annotationData[0:16]  (128 + 16 = 144 bytes)
 */
export async function decryptTransactCiphertext(
  ct: OnChainTransactCiphertext,
  viewingKey: Uint8Array,
): Promise<Note | null> {
  // Reconstruct ephemeral public key components
  const ephPubKeyX = ct.blindedSenderViewingKey;
  const ephPubKeyY = ct.blindedReceiverViewingKey;

  // Reconstruct the encrypted data: ciphertext[4] (128 bytes) + tag (16 bytes)
  const ct0 = hexToBytesStrict(ct.ciphertext[0]);
  const ct1 = hexToBytesStrict(ct.ciphertext[1]);
  const ct2 = hexToBytesStrict(ct.ciphertext[2]);
  const ct3 = hexToBytesStrict(ct.ciphertext[3]);
  const annotationBytes = hexToBytesStrict(ct.annotationData);

  // annotationData = tag (16 bytes) + nonce (24 bytes) = 40 bytes
  if (annotationBytes.length < 40) {
    return null;
  }

  const tag = annotationBytes.slice(0, 16);
  const nonce = annotationBytes.slice(16, 40);

  // Full encrypted data = 128 bytes (ciphertext) + 16 bytes (Poly1305 tag)
  const encryptedData = concatBytes(ct0, ct1, ct2, ct3, tag);

  // Convert to the internal CommitmentCiphertext format for decryptNote
  const internalCt: CommitmentCiphertext = {
    ephemeralPubKey: [ephPubKeyX, ephPubKeyY],
    nonce: bytesToHexStr(nonce),
    data: bytesToHexStr(encryptedData),
  };

  return decryptNote(internalCt, viewingKey);
}
