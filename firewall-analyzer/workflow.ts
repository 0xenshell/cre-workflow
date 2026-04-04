import {
	cre,
	getNetwork,
	type Runtime,
} from '@chainlink/cre-sdk'
import { z } from 'zod'
import {
	type Address,
	parseAbi,
	encodeAbiParameters,
	parseAbiParameters,
	keccak256,
	toBytes,
	toHex,
} from 'viem'

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

// ─── Log Trigger Callback ───────────────────────────────────
export const onActionSubmitted = (
	runtime: Runtime<Config>,
): string => {
	const config = runtime.config

	runtime.log('ActionSubmitted event detected')

	// TODO: Step 1 - Decode event data (actionId, agentId, instructionHash)
	// TODO: Step 2 - Fetch encrypted instruction from relay
	// TODO: Step 3 - Decrypt instruction inside TEE
	// TODO: Step 4 - Run analysis (Defender + Claude via Confidential HTTP)
	// TODO: Step 5 - Compute score and decision
	// TODO: Step 6 - Write report on-chain (resolveAction + updateThreatScore)

	runtime.log('Analysis pipeline placeholder - will be implemented step by step')

	return 'Pipeline pending'
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
