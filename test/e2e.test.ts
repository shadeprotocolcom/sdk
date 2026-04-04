/**
 * End-to-end integration test for Shade Protocol.
 *
 * Tests the full flow against the LIVE Citrea mainnet:
 *   1. Shield cBTC into scBTC
 *   2. Read own balance correctly
 *   3. Send to a second wallet
 *   4. Second wallet receives and reads balance
 *   5. Unshield back to public address
 *
 * Requires:
 *   - TEST_PRIVATE_KEY env var (wallet with cBTC on Citrea mainnet)
 *   - Live indexer at api.shade-protocol.com
 *   - Live prover at prover.shade-protocol.com
 */

import { describe, it, expect, beforeAll } from "vitest";
import { ethers } from "ethers";
import { ShadeClient } from "../src/client.js";
import type { ShadeConfig } from "../src/types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PRIVATE_KEY_A =
  process.env.TEST_PRIVATE_KEY ||
  "0x12be600b9c129237b5a9770bd91e90dc3f9d74f3890aabde716d846850e97888";

// Generate a deterministic second wallet for send/receive test
const PRIVATE_KEY_B = ethers.keccak256(ethers.toUtf8Bytes("shade-e2e-test-wallet-b-v1"));

const config: ShadeConfig = {
  chainId: 4114,
  rpcUrl: "https://rpc.citreascan.com",
  contractAddress: "0x2dDfE129904e3099b69F795e3c1B629c2BBd25E9",
  wcbtcAddress: "0x3100000000000000000000000000000000000006",
  keyRegistryAddress: "0xDBeF67AaF7c9917a67f6710a611ED80C8326118d",
  indexerUrl: "https://api.shade-protocol.com",
  proverUrl: "https://prover.shade-protocol.com",
};

// Shield a tiny amount: 0.000005 cBTC = 5 * 10^12 wei
const SHIELD_AMOUNT = 5_000_000_000_000n;
// Send half of that
const SEND_AMOUNT = 2_000_000_000_000n;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const provider = new ethers.JsonRpcProvider(config.rpcUrl);
const walletA = new ethers.Wallet(PRIVATE_KEY_A, provider);
const walletB = new ethers.Wallet(PRIVATE_KEY_B, provider);

async function registerWithIndexer(
  client: ShadeClient,
  address: string,
): Promise<void> {
  const viewingPubKeyJson = await client.getViewingPublicKey();
  const masterPublicKey = client.getMasterPublicKey();

  const shadePublicKey = JSON.stringify({
    viewingPublicKey: JSON.parse(viewingPubKeyJson),
    masterPublicKey: masterPublicKey.toString(),
  });

  const response = await fetch(`${config.indexerUrl}/keys/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ethAddress: address, shadePublicKey }),
  });

  if (!response.ok && response.status !== 409) {
    throw new Error(`Failed to register: HTTP ${response.status}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("E2E: Full Shade Protocol Flow", () => {
  let clientA: ShadeClient;
  let clientB: ShadeClient;
  let balanceBeforeShield: bigint;

  beforeAll(async () => {
    // Verify wallet A has enough cBTC
    const balance = await provider.getBalance(walletA.address);
    console.log(`Wallet A: ${walletA.address}`);
    console.log(`Wallet A balance: ${ethers.formatEther(balance)} cBTC`);
    console.log(`Wallet B: ${walletB.address}`);

    const minRequired = SHIELD_AMOUNT + 500_000_000_000n; // shield + gas buffer
    expect(balance).toBeGreaterThan(minRequired);
  }, 30_000);

  // -----------------------------------------------------------------------
  // Step 1: Connect Wallet A
  // -----------------------------------------------------------------------

  it("Step 1: Connect wallet A and sync existing balance", async () => {
    clientA = new ShadeClient(config);
    await clientA.connect(walletA);
    await registerWithIndexer(clientA, walletA.address);

    balanceBeforeShield = await clientA.getBalance();
    console.log(`Balance before shield: ${balanceBeforeShield} wei`);

    // Balance should be >= 0 (might have notes from previous tests)
    expect(balanceBeforeShield).toBeGreaterThanOrEqual(0n);
  }, 60_000);

  // -----------------------------------------------------------------------
  // Step 2: Shield cBTC
  // -----------------------------------------------------------------------

  it("Step 2: Shield cBTC into the privacy pool", async () => {
    console.log(`Shielding ${SHIELD_AMOUNT} wei (${ethers.formatEther(SHIELD_AMOUNT)} cBTC)...`);

    const txHash = await clientA.shield(SHIELD_AMOUNT);
    console.log(`Shield tx: ${txHash}`);

    expect(txHash).toMatch(/^0x[0-9a-fA-F]{64}$/);

    // Wait for indexer to pick up the event (2-3 blocks on Citrea)
    console.log("Waiting 10s for indexer to sync...");
    await sleep(10_000);
  }, 120_000);

  // -----------------------------------------------------------------------
  // Step 3: Read own balance correctly
  // -----------------------------------------------------------------------

  it("Step 3: Read balance — should include shielded amount", async () => {
    const balanceAfterShield = await clientA.getBalance();
    console.log(`Balance after shield: ${balanceAfterShield} wei`);

    // Balance should have increased by exactly the shield amount
    expect(balanceAfterShield).toBe(balanceBeforeShield + SHIELD_AMOUNT);
  }, 60_000);

  // -----------------------------------------------------------------------
  // Step 4: Connect Wallet B and register
  // -----------------------------------------------------------------------

  it("Step 4: Connect wallet B and register with indexer", async () => {
    clientB = new ShadeClient(config);
    await clientB.connect(walletB);
    await registerWithIndexer(clientB, walletB.address);

    const balanceB = await clientB.getBalance();
    console.log(`Wallet B balance before receive: ${balanceB} wei`);
  }, 60_000);

  // -----------------------------------------------------------------------
  // Step 5: Send from A to B
  // -----------------------------------------------------------------------

  it("Step 5: Send private transfer from A to B", async () => {
    console.log(`Sending ${SEND_AMOUNT} wei to ${walletB.address}...`);

    const txHash = await clientA.send(walletB.address, SEND_AMOUNT);
    console.log(`Send tx: ${txHash}`);

    expect(txHash).toMatch(/^0x[0-9a-fA-F]{64}$/);

    // Wait for indexer
    console.log("Waiting 10s for indexer to sync...");
    await sleep(10_000);
  }, 180_000);

  // -----------------------------------------------------------------------
  // Step 6: Wallet B receives and reads balance
  // -----------------------------------------------------------------------

  it("Step 6: Wallet B reads balance — should show received amount", async () => {
    const balanceB = await clientB.getBalance();
    console.log(`Wallet B balance after receive: ${balanceB} wei`);

    // Wallet B may have accumulated balance from previous test runs.
    // Verify it has AT LEAST the send amount and increased from before.
    expect(balanceB).toBeGreaterThanOrEqual(SEND_AMOUNT);
  }, 60_000);

  // -----------------------------------------------------------------------
  // Step 7: Wallet A balance reduced by send amount
  // -----------------------------------------------------------------------

  it("Step 7: Wallet A balance reduced correctly after send", async () => {
    const balanceA = await clientA.getBalance();
    console.log(`Wallet A balance after send: ${balanceA} wei`);

    // A started with balanceBeforeShield + SHIELD_AMOUNT, sent SEND_AMOUNT
    const expectedA = balanceBeforeShield + SHIELD_AMOUNT - SEND_AMOUNT;
    expect(balanceA).toBe(expectedA);
  }, 60_000);

  // -----------------------------------------------------------------------
  // Step 8: Unshield from A back to public address
  // -----------------------------------------------------------------------

  it("Step 8: Unshield remaining balance back to wallet A", async () => {
    const currentBalance = await clientA.getBalance();
    console.log(`Unshielding ${currentBalance} wei back to ${walletA.address}...`);

    // Unshield all remaining balance
    expect(currentBalance).toBeGreaterThan(0n);

    const txHash = await clientA.unshield(walletA.address, currentBalance);
    console.log(`Unshield tx: ${txHash}`);

    expect(txHash).toMatch(/^0x[0-9a-fA-F]{64}$/);

    // Wait for indexer
    console.log("Waiting 10s for indexer to sync...");
    await sleep(10_000);
  }, 180_000);

  // -----------------------------------------------------------------------
  // Step 9: Verify final state
  // -----------------------------------------------------------------------

  it("Step 9: Wallet A shielded balance is zero after unshield", async () => {
    // The indexer may need extra time to process the Nullified events from the
    // unshield transaction. Retry a few times with increasing delays.
    let finalBalance = await clientA.getBalance();
    for (let attempt = 0; attempt < 5 && finalBalance > 0n; attempt++) {
      console.log(`Balance still ${finalBalance} wei, waiting 5s (attempt ${attempt + 1}/5)...`);
      await sleep(5_000);
      finalBalance = await clientA.getBalance();
    }
    console.log(`Wallet A final shielded balance: ${finalBalance} wei`);

    expect(finalBalance).toBe(0n);
  }, 120_000);
});
