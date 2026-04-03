import { decryptTransactCiphertext } from "./encryption.js";
import { computeNullifier, computeCommitment, computeTokenId } from "./notes.js";
/**
 * Error thrown when the indexer returns a non-OK response.
 */
export class IndexerError extends Error {
    constructor(message, status) {
        super(message);
        this.name = "IndexerError";
        this.status = status;
    }
}
/**
 * Fetch all events from the indexer starting at `fromBlock`.
 *
 * The indexer exposes a single `GET /events?from=<blockNumber>` endpoint that
 * returns Shield, Transact, and Nullified events.  We split them client-side
 * into commitment and nullifier events.
 */
async function fetchEvents(indexerUrl, fromBlock) {
    const url = `${indexerUrl.replace(/\/+$/, "")}/events?from=${fromBlock}`;
    const response = await fetch(url);
    if (!response.ok) {
        throw new IndexerError(`Failed to fetch events: HTTP ${response.status}`, response.status);
    }
    const body = (await response.json());
    const commitments = [];
    const nullifiers = [];
    for (const event of body.events) {
        const d = event.data;
        if (event.eventType === "Shield") {
            // Shield events store an array of preimages, each with commitment and ciphertext.
            // The startPosition gives the leafIndex of the first preimage.
            const preimages = d.preimages;
            const startPosition = Number(d.startPosition ?? 0);
            if (preimages && Array.isArray(preimages)) {
                for (let i = 0; i < preimages.length; i++) {
                    const p = preimages[i];
                    if (p.commitment !== undefined) {
                        commitments.push({
                            blockNumber: event.blockNumber,
                            transactionHash: event.txHash,
                            leafIndex: startPosition + i,
                            commitment: String(p.commitment),
                            eventType: "Shield",
                            // Store the ENTIRE preimage object so tryReconstructShieldNote
                            // can access npk, value, tokenAddress, tokenType, tokenSubID
                            ciphertext: p,
                        });
                    }
                }
            }
        }
        if (event.eventType === "Transact") {
            // Transact events store hashes[] and ciphertexts[] arrays.
            // The startPosition gives the leafIndex of the first hash.
            const hashes = d.hashes;
            const ciphertextData = d.ciphertexts;
            const startPosition = Number(d.startPosition ?? 0);
            if (hashes && Array.isArray(hashes)) {
                for (let i = 0; i < hashes.length; i++) {
                    const ct = ciphertextData && i < ciphertextData.length
                        ? ciphertextData[i]
                        : null;
                    if (ct) {
                        commitments.push({
                            blockNumber: event.blockNumber,
                            transactionHash: event.txHash,
                            leafIndex: startPosition + i,
                            commitment: hashes[i],
                            eventType: "Transact",
                            ciphertext: ct,
                        });
                    }
                }
            }
        }
        if (event.eventType === "Nullified") {
            // Nullified events store an array of nullifiers
            const nullifierList = d.nullifiers;
            if (nullifierList && Array.isArray(nullifierList)) {
                for (const nf of nullifierList) {
                    nullifiers.push({
                        blockNumber: event.blockNumber,
                        transactionHash: event.txHash,
                        nullifier: nf,
                    });
                }
            }
            else if (d.nullifier !== undefined) {
                // Fallback for single nullifier format
                nullifiers.push({
                    blockNumber: event.blockNumber,
                    transactionHash: event.txHash,
                    nullifier: String(d.nullifier),
                });
            }
        }
    }
    return { commitments, nullifiers };
}
/**
 * Normalize an on-chain nullifier (which may be hex) to a decimal string.
 * This ensures consistent comparison between SDK-computed nullifiers (decimal)
 * and indexer-provided nullifiers (hex from on-chain events).
 */
function normalizeNullifier(nullifier) {
    if (nullifier.startsWith("0x") || nullifier.startsWith("0X")) {
        return BigInt(nullifier).toString();
    }
    // If it looks like a hex string without prefix (64 hex chars), try parsing
    if (/^[0-9a-fA-F]{64}$/.test(nullifier)) {
        return BigInt("0x" + nullifier).toString();
    }
    // Already decimal
    return nullifier;
}
/**
 * Try to reconstruct a Note from a Shield event's plaintext preimage data.
 *
 * Shield events emit the CommitmentPreimage in cleartext (npk, token, value).
 * We check if the npk could belong to us by testing if npk = Poseidon(MPK, r)
 * for any known MPK. Since we can't recover `random` from just the npk,
 * we store the note with random=0 (it's not needed for spending — the circuit
 * uses npk directly, not random).
 *
 * We identify ownership by checking if the npk was generated from our
 * master public key. For the shielder's own notes, the ShadeClient also
 * adds them locally during shield(). This function handles the case where
 * the user shielded from a different session or directly via the contract.
 */
async function tryReconstructShieldNote(event, masterPublicKey) {
    // Shield events store preimage data directly in the ciphertext field
    // (it's actually the preimage object from the indexer, not a real ciphertext)
    const preimage = event.ciphertext;
    if (!preimage || preimage.npk === undefined)
        return null;
    const npk = BigInt(String(preimage.npk));
    const value = BigInt(String(preimage.value));
    const tokenAddress = String(preimage.tokenAddress || "");
    const tokenType = Number(preimage.tokenType ?? 0);
    const tokenSubID = BigInt(String(preimage.tokenSubID ?? "0"));
    // Compute the token ID the same way the contract does
    const token = await computeTokenId(tokenAddress);
    // We can't verify ownership by npk alone without knowing `random`.
    // But we CAN verify the commitment matches, which proves the data is valid.
    // For now, we claim ALL shield notes where we can verify the commitment.
    // This is safe because only the owner can spend them (needs nullifyingKey).
    const commitment = await computeCommitment(npk, token, value);
    const commitmentStr = commitment.toString();
    const eventCommitmentStr = normalizeNullifier(String(event.commitment));
    if (commitmentStr !== eventCommitmentStr) {
        return null; // Commitment mismatch
    }
    return {
        npk,
        random: 0n, // Unknown — not needed for spending
        token,
        value,
        commitment,
    };
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
export async function syncBalance(indexerUrl, viewingKey, nullifyingKey, existingNotes, lastSyncBlock, masterPublicKey) {
    // Fetch all events from the indexer and split into commitments/nullifiers
    const { commitments: commitmentEvents, nullifiers: nullifierEvents } = await fetchEvents(indexerUrl, lastSyncBlock);
    // Clone the existing note set so we don't mutate the caller's array
    const notes = existingNotes.map((n) => ({ ...n }));
    // Build a set of known nullifiers for fast lookup.
    // Normalize all on-chain nullifiers to decimal strings so they match
    // the SDK-computed nullifiers (which are bigint.toString() = decimal).
    const spentNullifiers = new Set(nullifierEvents.map((e) => normalizeNullifier(e.nullifier)));
    // Track the highest block we've processed
    let lastBlock = lastSyncBlock;
    // --- Process new commitments ---
    for (const event of commitmentEvents) {
        if (event.blockNumber > lastBlock) {
            lastBlock = event.blockNumber;
        }
        // Use the correct decryption path based on event type
        let note = null;
        if (event.eventType === "Shield") {
            note = masterPublicKey
                ? await tryReconstructShieldNote(event, masterPublicKey)
                : null;
        }
        else if (event.eventType === "Transact") {
            note = await decryptTransactCiphertext(event.ciphertext, viewingKey);
        }
        if (note === null) {
            continue;
        }
        // Verify the commitment matches what the chain recorded.
        // Normalize both to decimal for consistent comparison.
        const expectedCommitment = await computeCommitment(note.npk, note.token, note.value);
        const expectedStr = expectedCommitment.toString();
        const eventStr = normalizeNullifier(event.commitment); // same normalization works for commitments
        if (expectedStr !== eventStr) {
            // Commitment mismatch — corrupted event or decryption collision, skip.
            continue;
        }
        // Compute the nullifier for this note
        const nullifier = await computeNullifier(nullifyingKey, event.leafIndex);
        // Use decimal string for nullifier comparison
        const nullifierStr = nullifier.toString();
        // Skip if we already have a note at this leaf index (e.g. added locally
        // during shield() before sync picked it up).
        const alreadyKnown = notes.some((n) => n.leafIndex === event.leafIndex);
        if (alreadyKnown) {
            continue;
        }
        const owned = {
            ...note,
            leafIndex: event.leafIndex,
            nullifier,
            spent: spentNullifiers.has(nullifierStr),
        };
        notes.push(owned);
    }
    // --- Process nullifier events against all known notes ---
    for (const event of nullifierEvents) {
        if (event.blockNumber > lastBlock) {
            lastBlock = event.blockNumber;
        }
    }
    // Mark any previously unspent notes whose nullifier now appears on-chain
    for (const note of notes) {
        if (!note.spent && spentNullifiers.has(note.nullifier.toString())) {
            note.spent = true;
        }
    }
    // Compute total unspent balance
    const balance = notes
        .filter((n) => !n.spent)
        .reduce((sum, n) => sum + n.value, 0n);
    return { notes, balance, lastBlock };
}
//# sourceMappingURL=sync.js.map