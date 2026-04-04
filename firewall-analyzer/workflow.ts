import {
	CronCapability,
	handler,
	type Runtime,
} from '@chainlink/cre-sdk'
import { z } from 'zod'
import { getPublicKey, getSharedSecret } from '@noble/secp256k1'
import { gcm } from '@noble/ciphers/aes.js'
import { sha256 } from '@noble/hashes/sha2.js'

// ─── Config Schema ──────────────────────────────────────────
export const configSchema = z.object({
	schedule: z.string(),
})
type Config = z.infer<typeof configSchema>

// ─── Crypto Test ────────────────────────────────────────────
function testCrypto(runtime: Runtime<Config>): string {
	// Generate a keypair (simulating the CRE oracle)
	const privateKey = sha256(new TextEncoder().encode('test-private-key-for-simulation'))
	const publicKey = getPublicKey(privateKey, true) // compressed

	runtime.log(`Public key (hex): ${Buffer.from(publicKey).toString('hex')}`)

	// Simulate SDK encryption
	const message = 'Send 0.05 ETH to treasury for weekly budget'
	const ephemeralPrivate = sha256(new TextEncoder().encode('ephemeral-key-for-test'))
	const ephemeralPublic = getPublicKey(ephemeralPrivate, true)

	// ECDH: SDK derives shared secret using oracle's public key
	const sharedSecretSDK = getSharedSecret(ephemeralPrivate, publicKey)
	const aesKeySDK = sha256(sharedSecretSDK)

	// Encrypt
	const nonce = new Uint8Array(12) // zero nonce for test
	const cipher = gcm(aesKeySDK, nonce)
	const plaintext = new TextEncoder().encode(message)
	const ciphertext = cipher.encrypt(plaintext)

	runtime.log(`Encrypted length: ${ciphertext.length}`)

	// Simulate CRE decryption
	const sharedSecretCRE = getSharedSecret(privateKey, ephemeralPublic)
	const aesKeyCRE = sha256(sharedSecretCRE)

	const decipher = gcm(aesKeyCRE, nonce)
	const decrypted = decipher.decrypt(ciphertext)
	const decryptedText = new TextDecoder().decode(decrypted)

	runtime.log(`Decrypted: ${decryptedText}`)

	const success = decryptedText === message
	runtime.log(`Crypto roundtrip: ${success ? 'SUCCESS' : 'FAILED'}`)

	return success ? 'Crypto works in CRE WASM!' : 'CRYPTO FAILED'
}

// ─── Workflow Init ──────────────────────────────────────────
export function initWorkflow(config: Config) {
	const cron = new CronCapability()
	return [
		handler(cron.trigger({ schedule: config.schedule }), testCrypto),
	]
}
