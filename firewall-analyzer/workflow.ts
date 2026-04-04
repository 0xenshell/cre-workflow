import {
	cre,
	getNetwork,
	sendRequest,
	type Runtime,
} from '@chainlink/cre-sdk'
import { z } from 'zod'
import {
	type Address,
	parseAbi,
	encodeAbiParameters,
	parseAbiParameters,
	decodeAbiParameters,
	keccak256,
	toBytes,
	toHex,
} from 'viem'
import { getSharedSecret } from '@noble/secp256k1'
import { gcm } from '@noble/ciphers/aes.js'
import { sha256 } from '@noble/hashes/sha2.js'

// ─── Config Schema ──────────────────────────────────────────
export const configSchema = z.object({
	chainSelectorName: z.string(),
	firewallContractAddress: z.string(),
	relayUrl: z.string(),
})
type Config = z.infer<typeof configSchema>

// ─── AgentFirewall ABI ──────────────────────────────────────
const FIREWALL_ABI = parseAbi([
	'event ActionSubmitted(uint256 indexed actionId, string indexed agentId, address target, uint256 value, bytes32 instructionHash)',
	'function onReport(bytes metadata, bytes report) external',
])

// ─── ActionSubmitted event signature ────────────────────────
const ACTION_SUBMITTED_SIG = keccak256(
	toBytes('ActionSubmitted(uint256,string,address,uint256,bytes32)')
)

// ─── Relay Response Schema ───────────────────────────────────
const relayResponseSchema = z.object({
	hash: z.string(),
	encryptedPayload: z.string(),
})

// ─── Fetch Encrypted Instruction from Relay ─────────────────
function fetchFromRelay(
	runtime: Runtime<Config>,
	instructionHash: string,
): string {
	const config = runtime.config
	const url = `${config.relayUrl}/relay/${instructionHash}`

	runtime.log(`Fetching from relay: ${url}`)

	const response = sendRequest(runtime, {
		url,
		method: 'GET',
		responseSchema: relayResponseSchema,
	})

	runtime.log(`Relay response received: payload length ${response.encryptedPayload.length}`)
	return response.encryptedPayload
}

// ─── Decrypt Instruction Inside TEE ─────────────────────────
function decryptInstruction(
	runtime: Runtime<Config>,
	encryptedHex: string,
	privateKeyHex: string,
): string {
	// Remove 0x prefix and convert to bytes
	const clean = encryptedHex.replace('0x', '')
	const packed = new Uint8Array(clean.length / 2)
	for (let i = 0; i < packed.length; i++) {
		packed[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16)
	}

	// Unpack: ephemeralPublic (33) + nonce (12) + ciphertext (rest)
	const ephemeralPublic = packed.slice(0, 33)
	const nonce = packed.slice(33, 45)
	const ciphertext = packed.slice(45)

	// ECDH to derive shared secret
	const privBytes = new Uint8Array(privateKeyHex.replace('0x', '').length / 2)
	for (let i = 0; i < privBytes.length; i++) {
		privBytes[i] = parseInt(privateKeyHex.replace('0x', '').substring(i * 2, i * 2 + 2), 16)
	}

	const sharedSecret = getSharedSecret(privBytes, ephemeralPublic)
	const aesKey = sha256(sharedSecret)

	// AES-256-GCM decrypt
	const decipher = gcm(aesKey, nonce)
	const decrypted = decipher.decrypt(ciphertext)

	const plaintext = new TextDecoder().decode(decrypted)
	runtime.log(`Decrypted instruction: ${plaintext.substring(0, 50)}...`)

	return plaintext
}

// ─── Log Trigger Callback ───────────────────────────────────
export const onActionSubmitted = (
	runtime: Runtime<Config>,
): string => {
	const config = runtime.config

	runtime.log('ActionSubmitted event detected')

	// TODO: Step 1 - Decode event data (actionId, agentId, instructionHash) from trigger payload
	// For now, using placeholder values until we wire up the trigger payload decoding
	const instructionHash = '0x0000000000000000000000000000000000000000000000000000000000000000'

	// Step 2 - Fetch encrypted instruction from relay
	// const encryptedPayload = fetchFromRelay(runtime, instructionHash)

	// TODO: Step 3 - Decrypt instruction inside TEE
	// TODO: Step 4 - Run analysis (Defender + Claude via Confidential HTTP)
	// TODO: Step 5 - Compute score and decision
	// TODO: Step 6 - Write report on-chain (resolveAction + updateThreatScore)

	runtime.log('Relay fetch ready, remaining pipeline steps pending')

	return 'Relay fetch implemented'
}

// ─── Workflow Init ──────────────────────────────────────────
export function initWorkflow(config: Config) {
	const network = getNetwork({
		chainFamily: 'evm',
		chainSelectorName: config.chainSelectorName,
		isTestnet: true,
	})
	if (!network) throw new Error(`Network not found: ${config.chainSelectorName}`)

	const evmClient = new cre.capabilities.EVMClient(network.chainSelector.selector)

	// Listen for ActionSubmitted events on the AgentFirewall contract
	const actionSubmittedTrigger = evmClient.logTrigger({
		contractAddress: config.firewallContractAddress as Address,
		eventSignature: ACTION_SUBMITTED_SIG,
	})

	return [
		cre.handler(
			actionSubmittedTrigger,
			onActionSubmitted,
		),
	]
}
