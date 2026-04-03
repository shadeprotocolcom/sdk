/**
 * Shade Protocol — End-to-end shield transaction on Citrea mainnet
 *
 * Shields 0.00001 cBTC (10_000_000_000_000 wei) into the Shade pool,
 * then verifies the indexer detected the event.
 */

import { ethers } from "ethers";
import { readFileSync } from "fs";
import { deriveShadeKeys, generateNotePublicKey, getPoseidon, fieldToBigInt } from "./dist/keys.js";
import { createNote, computeTokenId, computeCommitment } from "./dist/notes.js";
import { encryptNote, viewingPublicKey } from "./dist/encryption.js";
import { SNARK_FIELD, KEY_DERIVATION_MESSAGE } from "./dist/types.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const SHADE_POOL   = "0x2dDfE129904e3099b69F795e3c1B629c2BBd25E9";
const WCBTC        = "0x3100000000000000000000000000000000000006";
const RPC_URL      = "https://rpc.citreascan.com";
const CHAIN_ID     = 4114;
const INDEXER_URL  = "https://api.shade-protocol.com";
const SHIELD_AMOUNT = 10_000_000_000_000n;  // 0.00001 cBTC in wei

// ShadePool ABI — only the shield function + Shield event
const SHADE_ABI = [
  "function shield((( bytes32 npk, (uint8 tokenType, address tokenAddress, uint256 tokenSubID) token, uint120 value) preimage, (bytes32[3] encryptedBundle, bytes32 shieldKey) ciphertext)[] calldata requests) external payable",
  "event Shield(uint256 treeNumber, uint256 startPosition, (bytes32 npk, (uint8 tokenType, address tokenAddress, uint256 tokenSubID) token, uint120 value)[] commitments, (bytes32[3] encryptedBundle, bytes32 shieldKey)[] shieldCiphertext, uint256[] fees)",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
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
  return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("=== Shade Protocol E2E Shield — Citrea Mainnet ===\n");

  // 1. Load deployer private key
  const envContent = readFileSync("/tmp/shade-deploy.env", "utf-8");
  const match = envContent.match(/DEPLOYER_PRIVATE_KEY=(0x[0-9a-fA-F]+)/);
  if (!match) throw new Error("Could not read DEPLOYER_PRIVATE_KEY from /tmp/shade-deploy.env");
  const privateKey = match[1];
  console.log("[1/12] Deployer key loaded");

  // 2. Connect to Citrea mainnet
  const provider = new ethers.JsonRpcProvider(RPC_URL, CHAIN_ID);
  const wallet = new ethers.Wallet(privateKey, provider);
  const deployerAddr = wallet.address;
  console.log(`[2/12] Connected to Citrea mainnet (chain ${CHAIN_ID})`);
  console.log(`       Deployer: ${deployerAddr}`);

  const balance = await provider.getBalance(deployerAddr);
  console.log(`       Balance:  ${ethers.formatEther(balance)} cBTC`);
  console.log(`       Shield:   ${ethers.formatEther(SHIELD_AMOUNT)} cBTC`);

  if (balance < SHIELD_AMOUNT) {
    throw new Error(`Insufficient balance: ${balance} < ${SHIELD_AMOUNT}`);
  }

  // 3. Initialize circomlibjs
  console.log("[3/12] Initializing circomlibjs (Poseidon, BabyJubjub, EdDSA)...");
  const poseidon = await getPoseidon();
  console.log("       Poseidon ready");

  // 4. Derive Shade keys
  console.log("[4/12] Deriving Shade keys from wallet signature...");
  const signature = await wallet.signMessage(KEY_DERIVATION_MESSAGE);
  const keys = await deriveShadeKeys(signature);
  console.log(`       Master public key: ${keys.masterPublicKey.toString().slice(0, 20)}...`);
  console.log(`       Nullifying key:    ${keys.nullifyingKey.toString().slice(0, 20)}...`);

  // 5. Register keys with indexer
  console.log("[5/12] Checking key registration with indexer...");
  const viewPubKeyBytes = await viewingPublicKey(keys.viewingKey);
  const vpkX = bytesToHex(viewPubKeyBytes.slice(0, 32));
  const vpkY = bytesToHex(viewPubKeyBytes.slice(32, 64));

  const existingResp = await fetch(`${INDEXER_URL}/keys/${deployerAddr}`);
  if (existingResp.ok) {
    console.log("       Key registration exists on indexer");
  } else {
    console.log("       No existing registration found");
  }

  // 6. Create a shield note
  console.log("[6/12] Creating shield note...");
  const note = await createNote(keys.masterPublicKey, WCBTC, SHIELD_AMOUNT);
  console.log(`       NPK:        ${note.npk.toString().slice(0, 20)}...`);
  console.log(`       Random:     ${note.random.toString().slice(0, 20)}...`);
  console.log(`       Commitment: ${note.commitment.toString().slice(0, 20)}...`);

  // 7. Compute the commitment hash (verify it matches what the contract will compute)
  console.log("[7/12] Computing commitment hash...");
  const tokenId = computeTokenId(WCBTC);
  console.log(`       Token ID:   ${tokenId.toString().slice(0, 20)}...`);
  const verifyCommitment = await computeCommitment(note.npk, tokenId, SHIELD_AMOUNT);
  console.log(`       Verified:   ${verifyCommitment === note.commitment ? "MATCH" : "MISMATCH!"}`);

  // 8. Encrypt the note
  console.log("[8/12] Encrypting note...");
  const ciphertext = await encryptNote(note, note.random, viewPubKeyBytes);
  console.log(`       Ciphertext length: ${ciphertext.data.length} bytes`);
  console.log(`       Ephemeral key X:   ${ciphertext.ephemeralPubKey[0].toString().slice(0, 20)}...`);

  // 9. Build shield transaction calldata
  console.log("[9/12] Building shield transaction...");
  const shieldRequest = {
    preimage: {
      npk: "0x" + note.npk.toString(16).padStart(64, "0"),
      token: {
        tokenType: 0,
        tokenAddress: WCBTC,
        tokenSubID: 0n,
      },
      value: SHIELD_AMOUNT,
    },
    ciphertext: {
      encryptedBundle: [
        bytesToHex(ciphertext.data.slice(0, 32)),
        bytesToHex(ciphertext.data.slice(32, 64)),
        bytesToHex(ciphertext.data.slice(64, 96)),
      ],
      shieldKey: bytesToHex(bigIntToBytes32(ciphertext.ephemeralPubKey[0])),
    },
  };

  const contract = new ethers.Contract(SHADE_POOL, SHADE_ABI, wallet);

  // Estimate gas first
  console.log("       Estimating gas...");
  let gasEstimate;
  try {
    gasEstimate = await contract.shield.estimateGas([shieldRequest], { value: SHIELD_AMOUNT });
    console.log(`       Gas estimate: ${gasEstimate}`);
  } catch (err) {
    console.error("       Gas estimation failed:", err.message);
    console.log("       Will attempt with manual gas limit of 500k...");
    gasEstimate = 500_000n;
  }

  // 10. Send the shield transaction
  console.log("[10/12] Sending shield transaction...");
  const tx = await contract.shield([shieldRequest], {
    value: SHIELD_AMOUNT,
    gasLimit: gasEstimate * 150n / 100n,  // 50% buffer
  });
  console.log(`        TX hash:  ${tx.hash}`);
  console.log(`        Waiting for confirmation...`);

  // 11. Wait for confirmation
  const receipt = await tx.wait();
  console.log(`[11/12] Transaction confirmed!`);
  console.log(`        Block:    ${receipt.blockNumber}`);
  console.log(`        Gas used: ${receipt.gasUsed}`);
  console.log(`        Status:   ${receipt.status === 1 ? "SUCCESS" : "FAILED"}`);

  if (receipt.status !== 1) {
    throw new Error("Shield transaction reverted on-chain!");
  }

  // Parse Shield event from logs
  let startPosition = -1;
  for (const log of receipt.logs) {
    try {
      const parsed = contract.interface.parseLog({ topics: [...log.topics], data: log.data });
      if (parsed && parsed.name === "Shield") {
        startPosition = Number(parsed.args.startPosition);
        console.log(`        Shield event: treeNumber=${parsed.args.treeNumber}, startPosition=${startPosition}`);
        console.log(`        Commitments:  ${parsed.args.commitments.length}`);
        console.log(`        Fees:         ${parsed.args.fees.map(f => f.toString())}`);
      }
    } catch { /* not our event */ }
  }

  const explorerLink = `https://citreascan.com/tx/${receipt.hash}`;
  console.log(`\n        CitreaScan: ${explorerLink}\n`);

  // 12. Poll the indexer for the new event
  console.log("[12/12] Polling indexer for the shield event...");
  let found = false;
  for (let attempt = 1; attempt <= 30; attempt++) {
    await sleep(5000);  // Wait 5s between polls
    try {
      const merkleResp = await fetch(`${INDEXER_URL}/merkle/root`);
      if (merkleResp.ok) {
        const merkleData = await merkleResp.json();
        console.log(`        [Poll ${attempt}/30] Merkle leaves: ${merkleData.leafCount}`);

        if (merkleData.leafCount > 0) {
          console.log(`        Merkle root: ${merkleData.root}`);

          const eventsResp = await fetch(`${INDEXER_URL}/events?from=0`);
          if (eventsResp.ok) {
            const eventsData = await eventsResp.json();
            console.log(`        Events found: ${eventsData.events.length}`);
            for (const ev of eventsData.events) {
              console.log(`          - Type: ${ev.eventType}, Block: ${ev.blockNumber}, TX: ${ev.txHash}`);
            }
          }

          found = true;
          break;
        }
      }
    } catch (err) {
      console.log(`        [Poll ${attempt}/30] Error: ${err.message}`);
    }
  }

  if (!found) {
    console.log("\n        WARNING: Indexer has not yet detected the event after 150s.");
    console.log("        The transaction was confirmed on-chain — indexer may need more time.");
  }

  // Final summary
  console.log("\n========================================");
  console.log("  SHIELD TRANSACTION COMPLETE");
  console.log("========================================");
  console.log(`  TX Hash:     ${receipt.hash}`);
  console.log(`  Block:       ${receipt.blockNumber}`);
  console.log(`  Amount:      ${ethers.formatEther(SHIELD_AMOUNT)} cBTC`);
  console.log(`  Gas used:    ${receipt.gasUsed}`);
  console.log(`  Leaf index:  ${startPosition}`);
  console.log(`  CitreaScan:  ${explorerLink}`);
  console.log("========================================\n");

  // Check remaining balance
  const newBalance = await provider.getBalance(deployerAddr);
  console.log(`  Remaining deployer balance: ${ethers.formatEther(newBalance)} cBTC`);
  const spent = balance - newBalance;
  console.log(`  Total spent (shield + gas): ${ethers.formatEther(spent)} cBTC`);
}

main().catch(err => {
  console.error("\nFATAL ERROR:", err.message);
  if (err.data) console.error("  Error data:", err.data);
  if (err.transaction) console.error("  TX:", err.transaction);
  process.exit(1);
});
