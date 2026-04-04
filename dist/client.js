import { ethers } from "ethers";
import { deriveShadeKeys } from "./keys.js";
import { createNote, computeCommitment, computeTokenId, computeNullifier, createDummyNoteWithTokenId } from "./notes.js";
import { encryptNote, viewingPublicKey } from "./encryption.js";
import { buildTransactWitness } from "./witness.js";
import { generateProof } from "./prover.js";
import { syncBalance } from "./sync.js";
import { KEY_DERIVATION_MESSAGE, } from "./types.js";
// ---------------------------------------------------------------------------
// Contract ABI (minimal subset needed by the client)
// ---------------------------------------------------------------------------
const SHADE_ABI = [
    // shield() takes an array of ShieldRequest structs
    "function shield((( bytes32 npk, (uint8 tokenType, address tokenAddress, uint256 tokenSubID) token, uint120 value) preimage, (bytes32[3] encryptedBundle, bytes32 shieldKey) ciphertext)[] calldata requests) external payable",
    // transact() takes an array of Transaction structs
    "function transact(((uint256[2] a, uint256[2][2] b, uint256[2] c) proof, bytes32 merkleRoot, bytes32[] nullifiers, bytes32[] commitments, (uint16 treeNumber, uint8 unshield, uint64 chainID, (bytes32[4] ciphertext, bytes32 blindedSenderViewingKey, bytes32 blindedReceiverViewingKey, bytes annotationData, bytes memo)[] commitmentCiphertext) boundParams, (bytes32 npk, (uint8 tokenType, address tokenAddress, uint256 tokenSubID) token, uint120 value) unshieldPreimage)[] calldata transactions) external",
    // Events matching the contract
    "event Shield(uint256 treeNumber, uint256 startPosition, (bytes32 npk, (uint8 tokenType, address tokenAddress, uint256 tokenSubID) token, uint120 value)[] commitments, (bytes32[3] encryptedBundle, bytes32 shieldKey)[] shieldCiphertext, uint256[] fees)",
    "event Transact(uint256 treeNumber, uint256 startPosition, bytes32[] hash, (bytes32[4] ciphertext, bytes32 blindedSenderViewingKey, bytes32 blindedReceiverViewingKey, bytes annotationData, bytes memo)[] ciphertext)",
    "event Nullified(uint16 treeNumber, bytes32[] nullifier)",
];
const ERC20_ABI = [
    "function approve(address spender, uint256 amount) external returns (bool)",
    "function allowance(address owner, address spender) view returns (uint256)",
];
const KEY_REGISTRY_ABI = [
    "function getKeys(address account) external view returns (bytes32, bytes32, bytes32)",
    "function isRegistered(address account) external view returns (bool)",
];
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function bigIntToHex(value) {
    return "0x" + value.toString(16);
}
function bigIntToBytes32(value) {
    const buf = new Uint8Array(32);
    let v = value;
    for (let i = 31; i >= 0; i--) {
        buf[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return buf;
}
function bytesToHex(bytes) {
    return ("0x" +
        Array.from(bytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""));
}
function bytesToBigInt(bytes) {
    let value = 0n;
    for (const b of bytes) {
        value = (value << 8n) + BigInt(b);
    }
    return value;
}
// ---------------------------------------------------------------------------
// ShadeClient
// ---------------------------------------------------------------------------
export class ShadeClient {
    constructor(config) {
        this.provider = null;
        this.signer = null;
        this.contract = null;
        this.wcbtcContract = null;
        this.keyRegistry = null;
        this.keys = null;
        this.ownedNotes = [];
        this.lastSyncBlock = 0;
        this.config = config;
    }
    // -----------------------------------------------------------------------
    // Connection & key derivation
    // -----------------------------------------------------------------------
    /**
     * Connect a signer, derive Shade keys, and perform initial balance sync.
     *
     * The signer is asked to sign the canonical key-derivation message.  The
     * resulting signature is used deterministically to derive spending, viewing
     * and nullifying keys.
     */
    async connect(signer) {
        this.signer = signer;
        this.provider = new ethers.JsonRpcProvider(this.config.rpcUrl);
        // Derive keys from wallet signature
        const signature = await signer.signMessage(KEY_DERIVATION_MESSAGE);
        this.keys = await deriveShadeKeys(signature);
        // Instantiate contracts
        this.contract = new ethers.Contract(this.config.contractAddress, SHADE_ABI, signer);
        this.wcbtcContract = new ethers.Contract(this.config.wcbtcAddress, ERC20_ABI, signer);
        this.keyRegistry = new ethers.Contract(this.config.keyRegistryAddress, KEY_REGISTRY_ABI, this.provider);
        // Initial sync
        await this.sync();
    }
    // -----------------------------------------------------------------------
    // Note persistence (for cross-session recovery)
    // -----------------------------------------------------------------------
    /**
     * Export owned notes as a JSON string for localStorage persistence.
     */
    exportNotes() {
        return JSON.stringify(this.ownedNotes.map((n) => ({
            npk: n.npk.toString(),
            random: n.random.toString(),
            token: n.token.toString(),
            value: n.value.toString(),
            commitment: n.commitment.toString(),
            leafIndex: n.leafIndex,
            nullifier: n.nullifier.toString(),
            spent: n.spent,
        })));
    }
    /**
     * Import previously exported notes (from localStorage).
     * Merges with existing notes, avoiding duplicates by leafIndex.
     */
    importNotes(json) {
        try {
            const parsed = JSON.parse(json);
            for (const n of parsed) {
                const leafIndex = Number(n.leafIndex);
                if (this.ownedNotes.some((existing) => existing.leafIndex === leafIndex)) {
                    continue; // Skip duplicates
                }
                this.ownedNotes.push({
                    npk: BigInt(String(n.npk)),
                    random: BigInt(String(n.random)),
                    token: BigInt(String(n.token)),
                    value: BigInt(String(n.value)),
                    commitment: BigInt(String(n.commitment)),
                    leafIndex,
                    nullifier: BigInt(String(n.nullifier)),
                    spent: Boolean(n.spent),
                });
            }
        }
        catch {
            // Invalid JSON, ignore
        }
    }
    // -----------------------------------------------------------------------
    // Public key access
    // -----------------------------------------------------------------------
    /**
     * Return the master public key derived during connect().
     */
    getMasterPublicKey() {
        this.assertConnected();
        return this.keys.masterPublicKey;
    }
    /**
     * Return the viewing public key (BabyJubjub point) as a JSON string.
     *
     * This is the key that should be registered with the indexer for recipient
     * lookups. Unlike the master public key (a single Poseidon hash), the viewing
     * public key is a full curve point that enables ECDH-based note encryption.
     *
     * Format: `{"x":"0x...","y":"0x..."}`
     */
    async getViewingPublicKey() {
        this.assertConnected();
        const pubKeyBytes = await viewingPublicKey(this.keys.viewingKey);
        const x = bytesToBigInt(pubKeyBytes.slice(0, 32));
        const y = bytesToBigInt(pubKeyBytes.slice(32, 64));
        return JSON.stringify({
            x: "0x" + x.toString(16).padStart(64, "0"),
            y: "0x" + y.toString(16).padStart(64, "0"),
        });
    }
    // -----------------------------------------------------------------------
    // Balance
    // -----------------------------------------------------------------------
    /**
     * Re-sync with the indexer and return the total unspent scBTC balance.
     */
    async getBalance() {
        await this.sync();
        return this.ownedNotes
            .filter((n) => !n.spent)
            .reduce((sum, n) => sum + n.value, 0n);
    }
    // -----------------------------------------------------------------------
    // Shield (deposit)
    // -----------------------------------------------------------------------
    /**
     * Deposit tokens into the Shade system, creating a shielded note.
     *
     * Sends native cBTC with `msg.value` — the contract auto-wraps it into
     * WcBTC internally. No ERC-20 approval step is needed.
     *
     * @param amount  Token amount in smallest unit (wei).
     * @returns       Transaction hash.
     */
    async shield(amount) {
        this.assertConnected();
        if (amount <= 0n) {
            throw new Error("Shield amount must be positive");
        }
        // Create a note for ourselves
        const note = await createNote(this.keys.masterPublicKey, this.config.wcbtcAddress, amount);
        // Encrypt the note for our own viewing key
        const viewPubKey = await viewingPublicKey(this.keys.viewingKey);
        const ciphertext = await encryptNote(note, note.random, viewPubKey);
        // Build ShieldRequest matching the contract's struct:
        // ShieldRequest { CommitmentPreimage preimage, ShieldCiphertext ciphertext }
        // CommitmentPreimage { bytes32 npk, TokenData token, uint120 value }
        // ShieldCiphertext { bytes32[3] encryptedBundle, bytes32 shieldKey }
        const shieldRequest = {
            preimage: {
                npk: "0x" + note.npk.toString(16).padStart(64, "0"),
                token: {
                    tokenType: 0, // ERC20
                    tokenAddress: this.config.wcbtcAddress,
                    tokenSubID: 0n,
                },
                value: amount,
            },
            ciphertext: {
                // Store the note's `random` value directly in encryptedBundle[0].
                // This allows recovery during sync — the random is needed to derive
                // NPK = Poseidon(MPK, random) which the circuit verifies.
                // encryptedBundle[1] stores the ephemeral pub key Y coordinate.
                // encryptedBundle[2] stores the nonce (first 24 bytes, zero-padded).
                // The actual encrypted payload is NOT needed for shield notes because
                // the preimage (npk, token, value) is emitted in cleartext in the event.
                // We just need `random` for spending.
                encryptedBundle: [
                    "0x" + note.random.toString(16).padStart(64, "0"),
                    "0x" + ciphertext.ephemeralPubKey[1].toString(16).padStart(64, "0"),
                    bytesToHex(new Uint8Array(32)), // padding
                ],
                // Store ephemeral public key x-coordinate
                shieldKey: bytesToHex(bigIntToBytes32(ciphertext.ephemeralPubKey[0])),
            },
        };
        // Send native cBTC as msg.value — the contract auto-wraps it into WcBTC
        const tx = await this.contract.shield([shieldRequest], { value: amount });
        const receipt = await tx.wait();
        // Add the shielded note to the local wallet immediately.
        // Shield ciphertexts cannot be fully decrypted from on-chain data alone
        // (only 96 of 144 bytes are stored), so syncBalance() skips Shield events.
        // We must add the note here to ensure it's available for spending.
        let leafIndex = 0;
        for (const log of receipt.logs) {
            try {
                const parsed = this.contract.interface.parseLog({
                    topics: [...log.topics],
                    data: log.data,
                });
                if (parsed && parsed.name === "Shield") {
                    leafIndex = Number(parsed.args.startPosition);
                    break;
                }
            }
            catch {
                // Not a matching event, skip
            }
        }
        const nullifier = await computeNullifier(this.keys.nullifyingKey, leafIndex);
        const ownedNote = {
            ...note,
            leafIndex,
            nullifier,
            spent: false,
        };
        // Avoid duplicates (e.g. if sync ran concurrently)
        const commitmentStr = ownedNote.commitment.toString();
        const alreadyExists = this.ownedNotes.some((n) => n.commitment.toString() === commitmentStr);
        if (!alreadyExists) {
            this.ownedNotes.push(ownedNote);
        }
        return receipt.hash;
    }
    // -----------------------------------------------------------------------
    // Send (private transfer)
    // -----------------------------------------------------------------------
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
    async send(recipientAddress, amount) {
        this.assertConnected();
        if (amount <= 0n) {
            throw new Error("Transfer amount must be positive");
        }
        if (!ethers.isAddress(recipientAddress)) {
            throw new Error(`Invalid recipient address: ${recipientAddress}`);
        }
        // Look up the recipient's registered key from the indexer
        const recipientKeyData = await this.fetchRecipientKey(recipientAddress);
        const recipientViewPubKey = this.parseViewingPublicKey(recipientKeyData);
        await this.sync();
        // Select input notes
        const { selected, total } = this.selectNotes(amount);
        if (total < amount) {
            throw new Error(`Insufficient balance: have ${total}, need ${amount}`);
        }
        // Build output notes
        // 1. Note to recipient (uses recipient's master public key derived
        //    from the viewing public key for note creation — but we need the
        //    MPK for npk derivation. We look it up alongside the viewing key.)
        const recipientNote = await createNote(recipientKeyData.masterPublicKey, this.config.wcbtcAddress, amount);
        // 2. Change note to ourselves (if any)
        const outputNotes = [recipientNote];
        const change = total - amount;
        if (change > 0n) {
            const changeNote = await createNote(this.keys.masterPublicKey, this.config.wcbtcAddress, change);
            outputNotes.push(changeNote);
        }
        // Build merkle tree with pre-fetched proofs for input notes
        const merkleTree = await this.prepareMerkleTree(selected.map((n) => n.leafIndex));
        // Encrypt output notes BEFORE computing the bound params hash,
        // because the hash now binds the ciphertext data to prevent
        // frontrunning attacks that swap ciphertexts.
        //
        // CRITICAL: Each note is encrypted with the CORRECT recipient's
        // viewing public key — the recipient's note with their key, and the
        // change note with our own key.
        const senderViewPubKey = await viewingPublicKey(this.keys.viewingKey);
        const ciphertexts = await Promise.all(outputNotes.map((note, index) => {
            // First output is always the recipient's note
            const encKey = index === 0 ? recipientViewPubKey : senderViewPubKey;
            return encryptNote(note, note.random, encKey);
        }));
        // Build formatted ciphertexts for bound params hash computation
        const commitmentCiphertexts = this.buildCommitmentCiphertexts(ciphertexts);
        // Compute bound params hash matching the contract's _hashBoundParams
        const boundParamsHash = this.computeBoundParamsHash(0, // unshield = UnshieldType.NONE
        0, // treeNumber
        commitmentCiphertexts);
        // Build witness
        const witness = await buildTransactWitness(selected, outputNotes, merkleTree, this.keys, boundParamsHash);
        // Generate proof
        const proof = await generateProof(witness, this.config.proverUrl);
        // Use nullifiers and commitments from the witness (includes padded dummies).
        // The contract expects exactly 2 of each, matching the 2-in-2-out circuit.
        const allNullifiers = witness.nullifiers.map((n) => BigInt(n));
        const allCommitments = witness.commitmentsOut.map((c) => BigInt(c));
        // Submit transaction
        return this.submitTransact(proof, merkleTree.root, boundParamsHash, allNullifiers, allCommitments, ciphertexts, ethers.ZeroAddress, 0n);
    }
    // -----------------------------------------------------------------------
    // Unshield (withdraw)
    // -----------------------------------------------------------------------
    /**
     * Withdraw from the Shade system back to a public address.
     *
     * @param toAddress  Destination Ethereum address.
     * @param amount     Token amount in smallest unit.
     * @returns          Transaction hash.
     */
    async unshield(toAddress, amount) {
        this.assertConnected();
        if (amount <= 0n) {
            throw new Error("Unshield amount must be positive");
        }
        if (!ethers.isAddress(toAddress)) {
            throw new Error(`Invalid address: ${toAddress}`);
        }
        await this.sync();
        const { selected, total } = this.selectNotes(amount);
        if (total < amount) {
            throw new Error(`Insufficient balance: have ${total}, need ${amount}`);
        }
        // The circuit enforces sumIn == sumOut. The unshield amount must appear
        // as a regular output note so the balance equation holds. The contract
        // recognizes this output by the npk field (set to the recipient address)
        // and transfers tokens instead of inserting it into the Merkle tree.
        //
        // CRITICAL: The contract checks txn.commitments[commitments.length - 1]
        // for the unshield hash, so the unshield note MUST be at the LAST position.
        const recipientAsBigInt = BigInt(toAddress);
        const tokenId = computeTokenId(this.config.wcbtcAddress);
        const unshieldCommitment = await computeCommitment(recipientAsBigInt, tokenId, amount);
        const unshieldNote = {
            npk: recipientAsBigInt,
            random: 0n, // Not meaningful for unshield outputs
            token: tokenId,
            value: amount,
            commitment: unshieldCommitment,
        };
        const outputNotes = [];
        // First slot: change note or dummy (unshield note must be LAST)
        const change = total - amount;
        if (change > 0n) {
            const changeNote = await createNote(this.keys.masterPublicKey, this.config.wcbtcAddress, change);
            outputNotes.push(changeNote);
        }
        else {
            // Pad with a dummy note so the unshield note lands at index 1 (last)
            const dummyNote = await createDummyNoteWithTokenId(this.keys.masterPublicKey, tokenId);
            outputNotes.push(dummyNote);
        }
        // Last slot: unshield note (contract expects it at commitments.length - 1)
        outputNotes.push(unshieldNote);
        const merkleTree = await this.prepareMerkleTree(selected.map((n) => n.leafIndex));
        // Encrypt output notes BEFORE computing the bound params hash
        const viewPubKey = await viewingPublicKey(this.keys.viewingKey);
        const ciphertexts = await Promise.all(outputNotes.map((note) => encryptNote(note, note.random, viewPubKey)));
        // Build formatted ciphertexts for bound params hash computation
        const commitmentCiphertexts = this.buildCommitmentCiphertexts(ciphertexts);
        // Compute bound params hash matching the contract's _hashBoundParams
        const boundParamsHash = this.computeBoundParamsHash(1, // unshield = UnshieldType.NORMAL
        0, // treeNumber
        commitmentCiphertexts);
        const witness = await buildTransactWitness(selected, outputNotes, merkleTree, this.keys, boundParamsHash);
        const proof = await generateProof(witness, this.config.proverUrl);
        // Use nullifiers and commitments from the witness (includes padded dummies).
        const allNullifiers = witness.nullifiers.map((n) => BigInt(n));
        const allCommitments = witness.commitmentsOut.map((c) => BigInt(c));
        return this.submitTransact(proof, merkleTree.root, boundParamsHash, allNullifiers, allCommitments, ciphertexts, toAddress, amount);
    }
    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------
    assertConnected() {
        if (!this.signer || !this.keys || !this.contract || !this.wcbtcContract || !this.keyRegistry || !this.provider) {
            throw new Error("ShadeClient is not connected. Call connect() first.");
        }
    }
    /**
     * Fetch a recipient's public keys.
     *
     * Checks the on-chain ShadeKeyRegistry first (trustless). If the recipient
     * has not self-registered on-chain, falls back to the centralized indexer.
     */
    async fetchRecipientKey(ethAddress) {
        // --- Try on-chain registry first ---
        try {
            const [vpkX, vpkY, mpk] = await this.keyRegistry.getKeys(ethAddress);
            if (mpk !== ethers.ZeroHash) {
                const x = "0x" + BigInt(vpkX).toString(16).padStart(64, "0");
                const y = "0x" + BigInt(vpkY).toString(16).padStart(64, "0");
                return {
                    viewingPublicKey: JSON.stringify({ x, y }),
                    masterPublicKey: BigInt(mpk),
                };
            }
        }
        catch {
            // On-chain lookup failed (e.g. network error), fall through to indexer
        }
        // --- Fallback: centralized indexer ---
        const baseUrl = this.config.indexerUrl.replace(/\/+$/, "");
        const response = await fetch(`${baseUrl}/keys/${ethAddress}`);
        if (!response.ok) {
            if (response.status === 404) {
                throw new Error(`Recipient ${ethAddress} is not registered with Shade Protocol`);
            }
            throw new Error(`Failed to look up recipient key: HTTP ${response.status}`);
        }
        const data = (await response.json());
        const keyData = JSON.parse(data.shadePublicKey);
        return {
            viewingPublicKey: JSON.stringify(keyData.viewingPublicKey),
            masterPublicKey: BigInt(keyData.masterPublicKey),
        };
    }
    /**
     * Parse a serialised viewing public key JSON string into the 64-byte
     * format expected by `encryptNote()`.
     *
     * Input:  `{"x":"0x...","y":"0x..."}`
     * Output: 64 bytes (x: 32 BE || y: 32 BE)
     */
    parseViewingPublicKey(keyData) {
        const parsed = JSON.parse(keyData.viewingPublicKey);
        const xBytes = bigIntToBytes32(BigInt(parsed.x));
        const yBytes = bigIntToBytes32(BigInt(parsed.y));
        const result = new Uint8Array(64);
        result.set(xBytes, 0);
        result.set(yBytes, 32);
        return result;
    }
    /**
     * Synchronise owned notes from the indexer.
     */
    async sync() {
        this.assertConnected();
        const result = await syncBalance(this.config.indexerUrl, this.keys.viewingKey, this.keys.nullifyingKey, this.ownedNotes, this.lastSyncBlock, this.keys.masterPublicKey);
        this.ownedNotes = result.notes;
        this.lastSyncBlock = result.lastBlock;
    }
    /**
     * Greedy note selection: pick unspent notes until their sum >= required amount.
     * Prefers larger notes first to minimise the number of inputs.
     */
    selectNotes(amount) {
        const unspent = this.ownedNotes
            .filter((n) => !n.spent && n.value > 0n)
            .sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0));
        const selected = [];
        let total = 0n;
        for (const note of unspent) {
            if (total >= amount)
                break;
            selected.push(note);
            total += note.value;
            // Circuit supports max 2 inputs
            if (selected.length >= 2)
                break;
        }
        if (total < amount && unspent.length > 2) {
            throw new Error("Cannot satisfy transfer with at most 2 notes. " +
                "Consolidate notes first by sending to yourself.");
        }
        return { selected, total };
    }
    /**
     * Fetch the current Merkle root and leaf count from the indexer, and
     * build a MerkleTree object that fetches individual proofs on demand.
     *
     * The indexer exposes:
     *   GET /merkle/root          -> { root, leafCount, treeNumber }
     *   GET /merkle/path/:index   -> { leafIndex, pathElements, indices }
     */
    async fetchMerkleTree() {
        const baseUrl = this.config.indexerUrl.replace(/\/+$/, "");
        // Fetch the current root
        const rootResponse = await fetch(`${baseUrl}/merkle/root`);
        if (!rootResponse.ok) {
            throw new Error(`Failed to fetch Merkle root: HTTP ${rootResponse.status}`);
        }
        const rootData = (await rootResponse.json());
        const root = BigInt(rootData.root);
        return {
            root,
            getProof(leafIndex) {
                // This is a synchronous interface required by the witness builder.
                // We pre-fetch proofs for the input notes before building the witness.
                // See fetchMerkleProof() for the async version used internally.
                throw new Error("Use fetchMerkleProof() for async path retrieval. " +
                    "Call prepareMerkleTree() instead of fetchMerkleTree().");
            },
        };
    }
    /**
     * Fetch a Merkle inclusion proof for a specific leaf index from the indexer.
     */
    async fetchMerkleProof(leafIndex) {
        const baseUrl = this.config.indexerUrl.replace(/\/+$/, "");
        const response = await fetch(`${baseUrl}/merkle/path/${leafIndex}`);
        if (!response.ok) {
            throw new Error(`Failed to fetch Merkle path for index ${leafIndex}: HTTP ${response.status}`);
        }
        const data = (await response.json());
        return {
            pathElements: data.pathElements.map((e) => BigInt(e)),
            pathIndices: data.indices,
        };
    }
    /**
     * Prepare a MerkleTree with pre-fetched proofs for the given leaf indices.
     * This fetches all needed proofs upfront so the synchronous getProof()
     * interface works correctly.
     */
    async prepareMerkleTree(leafIndices, inputNotes) {
        const baseUrl = this.config.indexerUrl.replace(/\/+$/, "");
        // Fetch root
        const rootResponse = await fetch(`${baseUrl}/merkle/root`);
        if (!rootResponse.ok) {
            throw new Error(`Failed to fetch Merkle root: HTTP ${rootResponse.status}`);
        }
        const rootData = (await rootResponse.json());
        const root = BigInt(rootData.root);
        // Identify which leaf indices are dummy notes (value=0).
        // Dummy notes don't need real Merkle proofs because the circuit
        // skips the Merkle check when valueIn[i] == 0.
        const dummyIndices = new Set();
        if (inputNotes) {
            for (const note of inputNotes) {
                if (note.value === 0n) {
                    dummyIndices.add(note.leafIndex);
                }
            }
        }
        // Only fetch proofs for real (non-dummy) notes
        const realIndices = leafIndices.filter((idx) => !dummyIndices.has(idx));
        const proofPromises = realIndices.map((idx) => this.fetchMerkleProof(idx));
        const proofs = await Promise.all(proofPromises);
        const proofMap = new Map();
        for (let i = 0; i < realIndices.length; i++) {
            proofMap.set(realIndices[i], proofs[i]);
        }
        // Create fake proof for dummy notes (all zeros, depth 16)
        const TREE_DEPTH = 16;
        const fakeProof = {
            pathElements: Array(TREE_DEPTH).fill(0n),
            pathIndices: Array(TREE_DEPTH).fill(0),
        };
        for (const idx of dummyIndices) {
            proofMap.set(idx, fakeProof);
        }
        return {
            root,
            getProof(leafIndex) {
                const proof = proofMap.get(leafIndex);
                if (!proof) {
                    // Return fake proof for dummy/padding notes.
                    // The circuit skips Merkle verification when valueIn[i] == 0,
                    // so the path content doesn't matter.
                    return {
                        pathElements: Array(TREE_DEPTH).fill(0n),
                        pathIndices: Array(TREE_DEPTH).fill(0),
                    };
                }
                return proof;
            },
        };
    }
    /**
     * Format raw encryption outputs into the CommitmentCiphertext structure
     * used by the contract's BoundParams and the bound params hash.
     */
    buildCommitmentCiphertexts(ciphertexts) {
        return ciphertexts.map((ct) => {
            const padded = new Uint8Array(Math.max(ct.data.length, 128));
            padded.set(ct.data);
            return {
                ciphertext: [
                    bytesToHex(padded.slice(0, 32)),
                    bytesToHex(padded.slice(32, 64)),
                    bytesToHex(padded.slice(64, 96)),
                    bytesToHex(padded.slice(96, 128)),
                ],
                blindedSenderViewingKey: bytesToHex(bigIntToBytes32(ct.ephemeralPubKey[0])),
                blindedReceiverViewingKey: bytesToHex(bigIntToBytes32(ct.ephemeralPubKey[1])),
                annotationData: bytesToHex(new Uint8Array([
                    ...(ct.data.length > 128 ? ct.data.slice(128) : new Uint8Array(0)),
                    ...ct.nonce,
                ])),
                memo: "0x",
            };
        });
    }
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
    computeBoundParamsHash(unshieldType, treeNumber = 0, commitmentCiphertexts = []) {
        // First, compute the ciphertext hash matching _hashCommitmentCiphertexts
        const ctParts = [];
        for (const ct of commitmentCiphertexts) {
            ctParts.push(ct.ciphertext[0], ct.ciphertext[1], ct.ciphertext[2], ct.ciphertext[3], ct.blindedSenderViewingKey, ct.blindedReceiverViewingKey, ct.annotationData, ct.memo);
        }
        const ciphertextHash = ethers.keccak256(ctParts.length > 0
            ? ethers.concat(ctParts)
            : "0x");
        // abi.encodePacked(uint16, uint8, uint64, bytes32) = 2 + 1 + 8 + 32 = 43 bytes
        const packed = new Uint8Array(43);
        // uint16 treeNumber (big-endian)
        packed[0] = (treeNumber >> 8) & 0xff;
        packed[1] = treeNumber & 0xff;
        // uint8 unshield
        packed[2] = unshieldType & 0xff;
        // uint64 chainID (big-endian)
        const chainId = BigInt(this.config.chainId);
        for (let i = 0; i < 8; i++) {
            packed[3 + i] = Number((chainId >> BigInt((7 - i) * 8)) & 0xffn);
        }
        // bytes32 ciphertextHash
        const ctHashBytes = ethers.getBytes(ciphertextHash);
        packed.set(ctHashBytes, 11);
        const hash = ethers.keccak256(packed);
        const SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
        return BigInt(hash) % SNARK_SCALAR_FIELD;
    }
    /**
     * Submit a transact transaction to the Shade contract.
     *
     * The contract expects `Transaction[]` where each Transaction has:
     *   proof, merkleRoot, nullifiers[], commitments[], boundParams, unshieldPreimage
     */
    async submitTransact(proof, merkleRoot, boundParamsHash, nullifiers, commitments, ciphertexts, unshieldTo, unshieldValue) {
        const proofFormatted = {
            a: proof.a.map((v) => BigInt(v)),
            b: proof.b.map((row) => row.map((v) => BigInt(v))),
            c: proof.c.map((v) => BigInt(v)),
        };
        // Use the shared helper so the ciphertext format is identical
        // to what was used when computing the boundParamsHash.
        const commitmentCiphertexts = this.buildCommitmentCiphertexts(ciphertexts);
        const isUnshield = unshieldTo !== ethers.ZeroAddress && unshieldValue > 0n;
        // Build the Transaction struct matching Types.sol
        const transaction = {
            proof: proofFormatted,
            merkleRoot: "0x" + merkleRoot.toString(16).padStart(64, "0"),
            nullifiers: nullifiers.map((n) => "0x" + n.toString(16).padStart(64, "0")),
            commitments: commitments.map((c) => "0x" + c.toString(16).padStart(64, "0")),
            boundParams: {
                treeNumber: 0,
                unshield: isUnshield ? 1 : 0, // UnshieldType enum
                chainID: this.config.chainId,
                commitmentCiphertext: commitmentCiphertexts,
            },
            unshieldPreimage: {
                npk: isUnshield
                    ? "0x" + BigInt(unshieldTo).toString(16).padStart(64, "0")
                    : ethers.ZeroHash,
                token: {
                    tokenType: 0, // ERC20
                    tokenAddress: this.config.wcbtcAddress,
                    tokenSubID: 0n,
                },
                value: isUnshield ? unshieldValue : 0n,
            },
        };
        // Contract expects an array of Transaction
        const tx = await this.contract.transact([transaction]);
        const receipt = await tx.wait();
        return receipt.hash;
    }
}
//# sourceMappingURL=client.js.map