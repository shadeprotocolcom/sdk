import { ethers } from "ethers";
import { type ShadeConfig } from "./types.js";
export declare class ShadeClient {
    private readonly config;
    private provider;
    private signer;
    private contract;
    private wcbtcContract;
    private keyRegistry;
    private keys;
    private ownedNotes;
    private lastSyncBlock;
    constructor(config: ShadeConfig);
    /**
     * Connect a signer, derive Shade keys, and perform initial balance sync.
     *
     * The signer is asked to sign the canonical key-derivation message.  The
     * resulting signature is used deterministically to derive spending, viewing
     * and nullifying keys.
     */
    connect(signer: ethers.Signer): Promise<void>;
    /**
     * Export owned notes as a JSON string for localStorage persistence.
     */
    exportNotes(): string;
    /**
     * Import previously exported notes (from localStorage).
     * Merges with existing notes, avoiding duplicates by leafIndex.
     */
    importNotes(json: string): void;
    /**
     * Return the master public key derived during connect().
     */
    getMasterPublicKey(): bigint;
    /**
     * Return the viewing public key (BabyJubjub point) as a JSON string.
     *
     * This is the key that should be registered with the indexer for recipient
     * lookups. Unlike the master public key (a single Poseidon hash), the viewing
     * public key is a full curve point that enables ECDH-based note encryption.
     *
     * Format: `{"x":"0x...","y":"0x..."}`
     */
    getViewingPublicKey(): Promise<string>;
    /**
     * Re-sync with the indexer and return the total unspent scBTC balance.
     */
    getBalance(): Promise<bigint>;
    /**
     * Deposit tokens into the Shade system, creating a shielded note.
     *
     * Sends native cBTC with `msg.value` — the contract auto-wraps it into
     * WcBTC internally. No ERC-20 approval step is needed.
     *
     * @param amount  Token amount in smallest unit (wei).
     * @returns       Transaction hash.
     */
    shield(amount: bigint): Promise<string>;
    /**
     * Send a private transfer to another Shade user.
     *
     * The recipient is identified by their Ethereum address. Their viewing
     * public key is looked up from the indexer's key registry automatically.
     * The recipient's output note is encrypted with the recipient's viewing
     * public key, while any change note is encrypted with the sender's.
     *
     * @param recipientAddress  Receiver's Ethereum address (0x...).
     * @param amount            Token amount in smallest unit.
     * @returns                 Transaction hash.
     */
    send(recipientAddress: string, amount: bigint): Promise<string>;
    /**
     * Withdraw from the Shade system back to a public address.
     *
     * @param toAddress  Destination Ethereum address.
     * @param amount     Token amount in smallest unit.
     * @returns          Transaction hash.
     */
    unshield(toAddress: string, amount: bigint): Promise<string>;
    private assertConnected;
    /**
     * Fetch a recipient's public keys.
     *
     * Checks the on-chain ShadeKeyRegistry first (trustless). If the recipient
     * has not self-registered on-chain, falls back to the centralized indexer.
     */
    private fetchRecipientKey;
    /**
     * Parse a serialised viewing public key JSON string into the 64-byte
     * format expected by `encryptNote()`.
     *
     * Input:  `{"x":"0x...","y":"0x..."}`
     * Output: 64 bytes (x: 32 BE || y: 32 BE)
     */
    private parseViewingPublicKey;
    /**
     * Synchronise owned notes from the indexer.
     */
    private sync;
    /**
     * Greedy note selection: pick unspent notes until their sum >= required amount.
     * Prefers larger notes first to minimise the number of inputs.
     */
    private selectNotes;
    /**
     * Fetch the current Merkle root and leaf count from the indexer, and
     * build a MerkleTree object that fetches individual proofs on demand.
     *
     * The indexer exposes:
     *   GET /merkle/root          -> { root, leafCount, treeNumber }
     *   GET /merkle/path/:index   -> { leafIndex, pathElements, indices }
     */
    private fetchMerkleTree;
    /**
     * Fetch a Merkle inclusion proof for a specific leaf index from the indexer.
     */
    private fetchMerkleProof;
    /**
     * Prepare a MerkleTree with pre-fetched proofs for the given leaf indices.
     * This fetches all needed proofs upfront so the synchronous getProof()
     * interface works correctly.
     */
    private prepareMerkleTree;
    /**
     * Format raw encryption outputs into the CommitmentCiphertext structure
     * used by the contract's BoundParams and the bound params hash.
     */
    private buildCommitmentCiphertexts;
    /**
     * Compute the bound parameters hash matching the contract's _hashBoundParams.
     *
     * The contract computes:
     *   keccak256(abi.encodePacked(treeNumber, uint8(unshield), chainID, ciphertextHash)) % SNARK_SCALAR_FIELD
     *
     * where ciphertextHash = keccak256 of all ciphertext fields concatenated.
     *
     * @param unshieldType         0 = NONE, 1 = NORMAL
     * @param treeNumber           Merkle tree number (defaults to 0)
     * @param commitmentCiphertexts Formatted ciphertext structs for hashing
     */
    private computeBoundParamsHash;
    /**
     * Submit a transact transaction to the Shade contract.
     *
     * The contract expects `Transaction[]` where each Transaction has:
     *   proof, merkleRoot, nullifiers[], commitments[], boundParams, unshieldPreimage
     */
    private submitTransact;
}
//# sourceMappingURL=client.d.ts.map