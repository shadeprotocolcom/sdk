import type { OwnedNote, SyncResult } from "./types.js";
/**
 * Error thrown when the indexer returns a non-OK response.
 */
export declare class IndexerError extends Error {
    readonly status: number;
    constructor(message: string, status: number);
}
/**
 * Synchronise the local note set against the indexer.
 *
 * For every new commitment event the function attempts to decrypt the
 * ciphertext with the provided viewing key. Successfully decrypted notes
 * are added to the owned set. Nullifier events mark existing owned notes
 * as spent.
 *
 * @param indexerUrl     Base URL of the indexer API (no trailing slash).
 * @param viewingKey     32-byte viewing private key.
 * @param nullifyingKey  The user's nullifying key (for computing note nullifiers).
 * @param existingNotes  Previously synced owned notes (carried over between calls).
 * @param lastSyncBlock  Block number of the last successful sync.
 * @returns              Updated note set, total unspent balance, and latest block.
 */
export declare function syncBalance(indexerUrl: string, viewingKey: Uint8Array, nullifyingKey: bigint, existingNotes: OwnedNote[], lastSyncBlock: number, masterPublicKey?: bigint): Promise<SyncResult>;
//# sourceMappingURL=sync.d.ts.map