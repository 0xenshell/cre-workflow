# ENShell CRE Workflow

[![CodeQuill – Verified authorship](https://app.codequill.xyz/badges/claim/48113dd8-3e96-4554-9ace-eb8f0705a2d6)](https://app.codequill.xyz/explore/0xenshell/cre-workflow)
[![CodeQuill – Latest snapshot](https://app.codequill.xyz/badges/snapshot/48113dd8-3e96-4554-9ace-eb8f0705a2d6)](https://app.codequill.xyz/explore/0xenshell/cre-workflow)
[![CodeQuill Trust Index](https://app.codequill.xyz/badges/trust/48113dd8-3e96-4554-9ace-eb8f0705a2d6)](https://app.codequill.xyz/explore/0xenshell/cre-workflow)

Chainlink CRE workflow for **ENShell**. Listens for `ActionSubmitted` events on the AgentFirewall contract, runs a 4-layer threat analysis inside a Trusted Execution Environment, and writes the verdict back on-chain.

## Architecture

```
ActionSubmitted event on-chain
  → CRE triggers
  → Fetches encrypted instruction from relay
  → Decrypts inside TEE (noble-crypto ECIES)
  → Analyzes with Claude via Confidential HTTP
  → Writes report on-chain (resolveAction + updateThreatScore)
```

All instruction data is encrypted end-to-end. The CRE oracle's private key is stored in the Chainlink Vault DON (threshold-encrypted across nodes). Not even node operators can see the plaintext instructions.

## Setup

### Prerequisites

- [CRE CLI installed](https://docs.chain.link/cre/getting-started/cli-installation)
- [Bun](https://bun.sh/) installed (for dependency management)
- A Claude API key from [Anthropic](https://console.anthropic.com/)

### Install dependencies

```bash
cd firewall-analyzer
bun install
```

### Generate Oracle Keypair

The oracle keypair is used for end-to-end encryption of instructions. The SDK encrypts with the public key, the CRE decrypts with the private key.

Generate a new keypair:

```bash
node -e "
const { utils, getPublicKey } = require('@noble/secp256k1');
const sk = utils.randomSecretKey();
const pk = getPublicKey(sk, true);
const skHex = Array.from(sk).map(b => b.toString(16).padStart(2, '0')).join('');
const pkHex = Array.from(pk).map(b => b.toString(16).padStart(2, '0')).join('');
console.log('ORACLE_PRIVATE_KEY=' + skHex);
console.log('ORACLE_PUBLIC_KEY=' + pkHex);
"
```

- **Private key** → goes in `.env` (for simulation) or Vault DON (for production)
- **Public key** → goes in the SDK's `NetworkConfig.oraclePublicKey` (safe to ship publicly)

### Configure secrets

Copy the example and fill in your keys:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `CRE_ETH_PRIVATE_KEY` | Ethereum private key for signing CRE transactions |
| `ANTHROPIC_API_KEY` | Claude API key for Confidential HTTP analysis |
| `ORACLE_PRIVATE_KEY` | secp256k1 private key for decrypting instructions in TEE |

## Simulate

Run the workflow simulation:

```bash
cre workflow simulate firewall-analyzer --target staging-settings
```

```bash
cre workflow simulate firewall-analyzer --target staging-settings --evm-tx-hash <TX_HASH> --evm-event-index 0 --trigger-index 0 --non-interactive --skip-type-checks --broadcast
```

This compiles the workflow to WASM and executes it locally, simulating the full pipeline:
1. Log trigger fires on `ActionSubmitted`
2. Encrypted instruction fetched from relay
3. Decrypted inside simulated TEE
4. Claude analysis via Confidential HTTP
5. Report written on-chain via MockForwarder

## Deploy (Production)

### Upload secrets to Vault DON

```bash
cre secrets create --secrets-path secrets.yaml --env-file .env
```

### Deploy the workflow

```bash
cre workflow deploy firewall-analyzer --target production-settings
```

### Activate

```bash
cre workflow activate firewall-analyzer
```

## Configuration

### `config.staging.json` / `config.production.json`

| Field | Description |
|---|---|
| `chainSelectorName` | Chainlink chain selector (e.g., `ethereum-testnet-sepolia`) |
| `firewallContractAddress` | Deployed AgentFirewall contract address |
| `relayUrl` | ENShell relay service URL |

### `secrets.yaml`

Maps secret names to environment variable names. Secrets are resolved from `.env` in simulation and from Vault DON in production.

## Self-Hosting

The CRE workflow is fully open source. To run your own:

1. Generate your own oracle keypair (see above)
2. Deploy your own relay service ([enshell-relay](https://github.com/0xenshell/relay))
3. Deploy the AgentFirewall contract with your forwarder address
4. Update `config.staging.json` / `config.production.json` with your addresses
5. Set your secrets in `.env`
6. Simulate and deploy

## License

MIT
