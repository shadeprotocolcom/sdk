/**
 * BabyJubjub subgroup order.
 */
export const BABYJUBJUB_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

/**
 * BN254 SNARK scalar field prime.
 */
export const SNARK_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Domain separator used when signing for key derivation.
 */
export const KEY_DERIVATION_MESSAGE = "Shade Protocol Key Derivation v1";

/**
 * Domain separator for viewing key derivation (appended to the signature hash).
 */
export const VIEWING_KEY_DOMAIN = "Shade Protocol Viewing Key v1";

/**
 * Full key set derived from a wallet signature.
 */
export interface ShadeKeys {
  /** Raw 32-byte seed used as the EdDSA private key input for circomlibjs. */
  spendingKey: Uint8Array;
  spendingPublicKey: [bigint, bigint];
  viewingKey: Uint8Array;
  nullifyingKey: bigint;
  masterPublicKey: bigint;
}

/**
 * A note represents a private UTXO in the Shade system.
 */
export interface Note {
  npk: bigint;
  random: bigint;
  token: bigint;
  value: bigint;
  commitment: bigint;
}

/**
 * A note that the local wallet owns and can spend.
 */
export interface OwnedNote extends Note {
  leafIndex: number;
  nullifier: bigint;
  spent: boolean;
}

/**
 * Ciphertext produced by encrypting a note for a receiver.
 */
export interface ShieldCiphertext {
  /** Ephemeral public key (BabyJubjub point, packed) */
  ephemeralPubKey: [bigint, bigint];
  /** XChaCha20-Poly1305 nonce (24 bytes) */
  nonce: Uint8Array;
  /** Encrypted payload (note fields + Poly1305 tag) */
  data: Uint8Array;
}

/**
 * Ciphertext as stored on-chain / returned by the indexer.
 * This is the internal SDK format used by decryptNote().
 */
export interface CommitmentCiphertext {
  /** Hex-encoded ephemeral public key components */
  ephemeralPubKey: [string, string];
  /** Hex-encoded nonce */
  nonce: string;
  /** Hex-encoded encrypted data */
  data: string;
}

/**
 * Shield ciphertext as stored on-chain (matches Solidity ShieldCiphertext).
 * encryptedBundle[3] = first 96 bytes of encrypted data, split into 3x bytes32.
 * shieldKey = ephemeral public key x-coordinate.
 */
export interface OnChainShieldCiphertext {
  encryptedBundle: [string, string, string];
  shieldKey: string;
}

/**
 * Transact ciphertext as stored on-chain (matches Solidity CommitmentCiphertext).
 * ciphertext[4] = first 128 bytes of encrypted data, split into 4x bytes32.
 * blindedSenderViewingKey = ephemeral public key x-coordinate.
 * blindedReceiverViewingKey = ephemeral public key y-coordinate.
 * annotationData = Poly1305 tag (16 bytes) + XChaCha20 nonce (24 bytes).
 * memo = unused.
 */
export interface OnChainTransactCiphertext {
  ciphertext: [string, string, string, string];
  blindedSenderViewingKey: string;
  blindedReceiverViewingKey: string;
  annotationData: string;
  memo: string;
}

/**
 * All values serialised as decimal strings for the SNARK circuit.
 */
export interface WitnessInput {
  merkleRoot: string;
  boundParamsHash: string;
  nullifiers: string[];
  commitmentsOut: string[];
  token: string;
  publicKey: string[];
  signature: string[];
  randomIn: string[];
  valueIn: string[];
  pathElements: string[][];
  leavesIndices: string[];
  nullifyingKey: string;
  npkOut: string[];
  valueOut: string[];
}

/**
 * Groth16 proof as returned by the prover and consumed by the contract.
 */
export interface SnarkProof {
  a: [string, string];
  b: [[string, string], [string, string]];
  c: [string, string];
}

/**
 * Merkle tree abstraction expected by the witness builder.
 */
export interface MerkleTree {
  root: bigint;
  getProof(leafIndex: number): {
    pathElements: bigint[];
    pathIndices: number[];
  };
}

/**
 * Result of a balance sync operation.
 */
export interface SyncResult {
  notes: OwnedNote[];
  balance: bigint;
  lastBlock: number;
}

/**
 * Top-level configuration for the ShadeClient.
 */
export interface ShadeConfig {
  chainId: number;
  rpcUrl: string;
  contractAddress: string;
  wcbtcAddress: string;
  indexerUrl: string;
  proverUrl: string;
}

/**
 * Commitment event as returned by the indexer.
 * The ciphertext field holds the raw on-chain data whose shape depends on
 * the event type (Shield vs Transact). Use `eventType` to determine which
 * decryption path to use.
 */
export interface IndexerCommitmentEvent {
  blockNumber: number;
  transactionHash: string;
  leafIndex: number;
  commitment: string;
  eventType: "Shield" | "Transact";
  ciphertext: OnChainShieldCiphertext | OnChainTransactCiphertext;
}

/**
 * Nullifier event as returned by the indexer.
 */
export interface IndexerNullifierEvent {
  blockNumber: number;
  transactionHash: string;
  nullifier: string;
}
