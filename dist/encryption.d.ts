import { type Note, type ShieldCiphertext, type CommitmentCiphertext, type OnChainShieldCiphertext, type OnChainTransactCiphertext } from "./types.js";
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
export declare function encryptNote(note: Note, senderRandom: bigint, receiverViewingPubKey: Uint8Array): Promise<ShieldCiphertext>;
/**
 * Attempt to decrypt a commitment ciphertext using the local viewing key.
 *
 * @param ciphertext   On-chain ciphertext (hex-encoded fields).
 * @param viewingKey   32-byte viewing private key (the SHA-256 derived secret).
 * @returns            The decrypted Note, or null if decryption fails (not ours).
 */
export declare function decryptNote(ciphertext: CommitmentCiphertext, viewingKey: Uint8Array): Promise<Note | null>;
/**
 * Compute the viewing public key from a viewing private key.
 *
 * viewingPub = viewingScalar * G (BabyJubjub base point)
 *
 * Returns 64 bytes: x (32 BE) || y (32 BE).
 */
export declare function viewingPublicKey(viewingKey: Uint8Array): Promise<Uint8Array>;
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
export declare function decryptShieldCiphertext(_ct: OnChainShieldCiphertext, _viewingKey: Uint8Array): Promise<Note | null>;
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
export declare function decryptTransactCiphertext(ct: OnChainTransactCiphertext, viewingKey: Uint8Array): Promise<Note | null>;
//# sourceMappingURL=encryption.d.ts.map