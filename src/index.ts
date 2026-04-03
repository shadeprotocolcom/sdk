// Types
export type {
  ShadeKeys,
  Note,
  OwnedNote,
  ShieldCiphertext,
  CommitmentCiphertext,
  OnChainShieldCiphertext,
  OnChainTransactCiphertext,
  WitnessInput,
  SnarkProof,
  MerkleTree,
  SyncResult,
  ShadeConfig,
  IndexerCommitmentEvent,
  IndexerNullifierEvent,
} from "./types.js";

export {
  BABYJUBJUB_ORDER,
  SNARK_FIELD,
  KEY_DERIVATION_MESSAGE,
  VIEWING_KEY_DOMAIN,
} from "./types.js";

// Keys
export {
  deriveShadeKeys,
  generateNotePublicKey,
  getPoseidon,
  getBabyjub,
  getEddsa,
  fieldToBigInt,
} from "./keys.js";

// Notes
export {
  computeCommitment,
  computeNullifier,
  computeTokenId,
  createNote,
  createNoteWithRandom,
  toOwnedNote,
  createDummyNote,
} from "./notes.js";

// Encryption
export {
  encryptNote,
  decryptNote,
  decryptShieldCiphertext,
  decryptTransactCiphertext,
  viewingPublicKey,
} from "./encryption.js";

// Witness
export { buildTransactWitness } from "./witness.js";

// Prover
export { generateProof, ProverError } from "./prover.js";

// Sync
export { syncBalance, IndexerError } from "./sync.js";

// Client
export { ShadeClient } from "./client.js";
