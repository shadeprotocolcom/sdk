import type { WitnessInput, SnarkProof } from "./types.js";

/**
 * Error thrown when the remote prover returns a non-OK response.
 */
export class ProverError extends Error {
  public readonly status: number;
  public readonly body: string;

  constructor(message: string, status: number, body: string) {
    super(message);
    this.name = "ProverError";
    this.status = status;
    this.body = body;
  }
}

/**
 * Send a witness to the remote prover and return the Groth16 proof.
 *
 * The prover is expected to:
 *   1. Accept a JSON-encoded WitnessInput at `POST /prove`.
 *   2. Run the circuit witness generation + Groth16 proving.
 *   3. Return `{ proof: { a, b, c } }` where a, b, c match the Solidity
 *      verifier's calldata layout.
 *
 * @param witness   Complete witness object (all values as decimal strings).
 * @param proverUrl Base URL of the prover server (no trailing slash).
 * @returns         SnarkProof suitable for on-chain verification.
 */
export async function generateProof(
  witness: WitnessInput,
  proverUrl: string,
): Promise<SnarkProof> {
  const url = `${proverUrl.replace(/\/+$/, "")}/prove`;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(witness),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new ProverError(
      `Prover returned HTTP ${response.status}: ${body.slice(0, 500)}`,
      response.status,
      body,
    );
  }

  const result = (await response.json()) as {
    proof?: {
      a?: [string, string];
      b?: [[string, string], [string, string]];
      c?: [string, string];
    };
  };

  if (!result.proof || !result.proof.a || !result.proof.b || !result.proof.c) {
    throw new ProverError(
      "Prover response missing proof fields",
      response.status,
      JSON.stringify(result),
    );
  }

  return {
    a: result.proof.a,
    b: result.proof.b,
    c: result.proof.c,
  };
}
