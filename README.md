# @shade-protocol/sdk

TypeScript SDK for Shade Protocol — key derivation, note management, encryption, witness building, and proof generation.

## Installation

```bash
npm install @shade-protocol/sdk
```

## Usage

```typescript
import { ShadeClient } from '@shade-protocol/sdk';

const client = new ShadeClient({
  chainId: 4114,
  rpcUrl: 'https://rpc.citreascan.com',
  contractAddress: '0x...',
  wcbtcAddress: '0x...',
  indexerUrl: 'https://api.shade-protocol.com',
  proverUrl: 'https://prover.shade-protocol.com',
});

// Connect wallet and derive keys
await client.connect(signer);

// Shield cBTC → scBTC
await client.shield(parseEther('0.01'));

// Check private balance
const balance = await client.getBalance();

// Send scBTC privately
await client.send('0xRecipient...', parseEther('0.005'));

// Unshield scBTC → cBTC
await client.unshield('0xMyAddress...', parseEther('0.005'));
```

## Modules

| Module | Description |
|---|---|
| `keys.ts` | Key derivation from wallet signature (EdDSA, BabyJubjub) |
| `notes.ts` | Note creation, commitment and nullifier computation |
| `encryption.ts` | XChaCha20-Poly1305 note encryption/decryption |
| `witness.ts` | Circuit witness builder with dummy note padding |
| `prover.ts` | Remote proof generation client |
| `sync.ts` | Balance sync via indexer events |
| `client.ts` | High-level `ShadeClient` orchestrator |

## Related Repos

- [circuits](https://github.com/shadeprotocolcom/circuits) — ZK circuits
- [contracts](https://github.com/shadeprotocolcom/contracts) — Smart contracts
- [frontend](https://github.com/shadeprotocolcom/frontend) — Web app

## License

MIT
