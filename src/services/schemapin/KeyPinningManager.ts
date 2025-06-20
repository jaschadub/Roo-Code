/**
 * TOFU (Trust-On-First-Use) key management for SchemaPin
 */

import * as vscode from "vscode"
import * as path from "path"
import { EventEmitter } from "events"
import {
	SchemaPinConfig,
	PinnedKeyInfo,
	PinningMode,
	PinningPolicy,
	PinningPromptResponse,
	SchemaPinError,
	SchemaPinErrorType,
} from "./types"

/**
 * Manages TOFU key pinning and storage for SchemaPin
 */
export class KeyPinningManager extends EventEmitter {
	private dbPath: string
	private pinnedKeys: Map<string, PinnedKeyInfo> = new Map()
	private domainPolicies: Map<string, PinningPolicy> = new Map()
	private isInitialized = false

	constructor(
		private context: vscode.ExtensionContext,
		private config: SchemaPinConfig,
	) {
		super()
		this.dbPath = this.getDbPath()
	}

	/**
	 * Initialize the key pinning manager
	 */
	async initialize(): Promise<void> {
		if (this.isInitialized) {
			return
		}

		try {
			await this.loadPinnedKeys()
			await this.loadDomainPolicies()
			this.isInitialized = true
		} catch (error) {
			throw new SchemaPinError(
				SchemaPinErrorType.DATABASE_ERROR,
				`Failed to initialize key pinning manager: ${error instanceof Error ? error.message : String(error)}`,
				{ dbPath: this.dbPath, originalError: error },
			)
		}
	}

	/**
	 * Pin a public key for a tool
	 */
	async pinKey(toolId: string, publicKeyPem: string, domain: string, developerName?: string): Promise<boolean> {
		this.ensureInitialized()

		try {
			const fingerprint = await this.calculateKeyFingerprint(publicKeyPem)
			const now = new Date()

			const keyInfo: PinnedKeyInfo = {
				toolId,
				publicKeyPem,
				domain,
				developerName,
				pinnedAt: now,
				lastVerified: now,
				fingerprint,
			}

			this.pinnedKeys.set(toolId, keyInfo)
			await this.savePinnedKeys()

			this.emit("keyPinned", {
				toolId,
				domain,
				fingerprint,
			})

			return true
		} catch (error) {
			throw new SchemaPinError(
				SchemaPinErrorType.DATABASE_ERROR,
				`Failed to pin key for tool ${toolId}: ${error instanceof Error ? error.message : String(error)}`,
				{ toolId, domain, originalError: error },
			)
		}
	}

	/**
	 * Get pinned key information for a tool
	 */
	async getPinnedKeyInfo(toolId: string): Promise<PinnedKeyInfo | null> {
		this.ensureInitialized()
		return this.pinnedKeys.get(toolId) || null
	}

	/**
	 * Check if a key is pinned for a tool
	 */
	async isKeyPinned(toolId: string): Promise<boolean> {
		this.ensureInitialized()
		return this.pinnedKeys.has(toolId)
	}

	/**
	 * Get the pinned public key for a tool
	 */
	async getPinnedKey(toolId: string): Promise<string | null> {
		this.ensureInitialized()
		const keyInfo = this.pinnedKeys.get(toolId)
		return keyInfo?.publicKeyPem || null
	}

	/**
	 * Update the last verified timestamp for a pinned key
	 */
	async updateLastVerified(toolId: string): Promise<boolean> {
		this.ensureInitialized()

		const keyInfo = this.pinnedKeys.get(toolId)
		if (!keyInfo) {
			return false
		}

		keyInfo.lastVerified = new Date()
		this.pinnedKeys.set(toolId, keyInfo)
		await this.savePinnedKeys()

		return true
	}

	/**
	 * List all pinned keys
	 */
	async listPinnedKeys(): Promise<PinnedKeyInfo[]> {
		this.ensureInitialized()
		return Array.from(this.pinnedKeys.values())
	}

	/**
	 * Remove a pinned key
	 */
	async removePinnedKey(toolId: string): Promise<boolean> {
		this.ensureInitialized()

		const existed = this.pinnedKeys.has(toolId)
		if (existed) {
			const keyInfo = this.pinnedKeys.get(toolId)!
			this.pinnedKeys.delete(toolId)
			await this.savePinnedKeys()

			this.emit("keyRevoked", {
				toolId,
				domain: keyInfo.domain,
				fingerprint: keyInfo.fingerprint,
			})
		}

		return existed
	}

	/**
	 * Set domain-level pinning policy
	 */
	async setDomainPolicy(domain: string, policy: PinningPolicy): Promise<void> {
		this.ensureInitialized()
		this.domainPolicies.set(domain, policy)
		await this.saveDomainPolicies()
	}

	/**
	 * Get domain-level pinning policy
	 */
	async getDomainPolicy(domain: string): Promise<PinningPolicy> {
		this.ensureInitialized()
		return this.domainPolicies.get(domain) || PinningPolicy.PROMPT
	}

	/**
	 * Interactive key pinning with user prompt
	 */
	async interactivePinKey(
		toolId: string,
		publicKeyPem: string,
		domain: string,
		developerName?: string,
	): Promise<boolean> {
		this.ensureInitialized()

		// Check domain policy first
		const domainPolicy = await this.getDomainPolicy(domain)

		switch (domainPolicy) {
			case PinningPolicy.ALLOW:
				return this.pinKey(toolId, publicKeyPem, domain, developerName)

			case PinningPolicy.DENY:
				throw new SchemaPinError(SchemaPinErrorType.USER_REJECTED, `Domain ${domain} is blocked by policy`)

			case PinningPolicy.PROMPT:
			default:
				return this.promptUserForKeyPinning(toolId, publicKeyPem, domain, developerName)
		}
	}

	/**
	 * Update configuration
	 */
	async updateConfig(newConfig: SchemaPinConfig): Promise<void> {
		this.config = newConfig

		// Update database path if changed
		const newDbPath = this.getDbPath()
		if (newDbPath !== this.dbPath) {
			this.dbPath = newDbPath
			if (this.isInitialized) {
				await this.loadPinnedKeys()
				await this.loadDomainPolicies()
			}
		}
	}

	/**
	 * Dispose of the key pinning manager
	 */
	async dispose(): Promise<void> {
		if (this.isInitialized) {
			await this.savePinnedKeys()
			await this.saveDomainPolicies()
		}

		this.removeAllListeners()
		this.pinnedKeys.clear()
		this.domainPolicies.clear()
		this.isInitialized = false
	}

	/**
	 * Get the database path for storing pinned keys
	 */
	private getDbPath(): string {
		if (this.config.dbPath) {
			return this.config.dbPath
		}

		// Use VSCode's global storage path
		const globalStoragePath = this.context.globalStorageUri.fsPath
		return path.join(globalStoragePath, "schemapin", "keys.json")
	}

	/**
	 * Calculate SHA-256 fingerprint of a public key
	 */
	private async calculateKeyFingerprint(publicKeyPem: string): Promise<string> {
		// For now, use a simple hash of the PEM content
		// In a full implementation, this would use proper cryptographic fingerprinting
		const encoder = new TextEncoder()
		const data = encoder.encode(publicKeyPem)
		const hashBuffer = await crypto.subtle.digest("SHA-256", data)
		const hashArray = Array.from(new Uint8Array(hashBuffer))
		const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("")
		return `sha256:${hashHex}`
	}

	/**
	 * Load pinned keys from storage
	 */
	private async loadPinnedKeys(): Promise<void> {
		try {
			const keysData = this.context.globalState.get<Record<string, any>>("schemapin.pinnedKeys", {})

			this.pinnedKeys.clear()
			for (const [toolId, keyData] of Object.entries(keysData)) {
				this.pinnedKeys.set(toolId, {
					...keyData,
					pinnedAt: new Date(keyData.pinnedAt),
					lastVerified: keyData.lastVerified ? new Date(keyData.lastVerified) : undefined,
				})
			}
		} catch (error) {
			console.error("Failed to load pinned keys:", error)
			// Continue with empty keys map
		}
	}

	/**
	 * Save pinned keys to storage
	 */
	private async savePinnedKeys(): Promise<void> {
		try {
			const keysData: Record<string, any> = {}

			for (const [toolId, keyInfo] of this.pinnedKeys.entries()) {
				keysData[toolId] = {
					...keyInfo,
					pinnedAt: keyInfo.pinnedAt.toISOString(),
					lastVerified: keyInfo.lastVerified?.toISOString(),
				}
			}

			await this.context.globalState.update("schemapin.pinnedKeys", keysData)
		} catch (error) {
			throw new SchemaPinError(
				SchemaPinErrorType.DATABASE_ERROR,
				`Failed to save pinned keys: ${error instanceof Error ? error.message : String(error)}`,
			)
		}
	}

	/**
	 * Load domain policies from storage
	 */
	private async loadDomainPolicies(): Promise<void> {
		try {
			const policiesData = this.context.globalState.get<Record<string, string>>("schemapin.domainPolicies", {})

			this.domainPolicies.clear()
			for (const [domain, policy] of Object.entries(policiesData)) {
				this.domainPolicies.set(domain, policy as PinningPolicy)
			}
		} catch (error) {
			console.error("Failed to load domain policies:", error)
			// Continue with empty policies map
		}
	}

	/**
	 * Save domain policies to storage
	 */
	private async saveDomainPolicies(): Promise<void> {
		try {
			const policiesData: Record<string, string> = {}

			for (const [domain, policy] of this.domainPolicies.entries()) {
				policiesData[domain] = policy
			}

			await this.context.globalState.update("schemapin.domainPolicies", policiesData)
		} catch (error) {
			throw new SchemaPinError(
				SchemaPinErrorType.DATABASE_ERROR,
				`Failed to save domain policies: ${error instanceof Error ? error.message : String(error)}`,
			)
		}
	}

	/**
	 * Prompt user for key pinning decision
	 */
	private async promptUserForKeyPinning(
		toolId: string,
		publicKeyPem: string,
		domain: string,
		developerName?: string,
	): Promise<boolean> {
		const fingerprint = await this.calculateKeyFingerprint(publicKeyPem)

		const message =
			`SchemaPin: Trust new key for ${toolId}?\n\n` +
			`Domain: ${domain}\n` +
			`Developer: ${developerName || "Unknown"}\n` +
			`Key Fingerprint: ${fingerprint.substring(0, 16)}...`

		const choice = await vscode.window.showWarningMessage(
			message,
			{ modal: true },
			"Trust and Pin",
			"Reject",
			"Always Trust Domain",
			"Always Reject Domain",
		)

		switch (choice) {
			case "Trust and Pin":
				return this.pinKey(toolId, publicKeyPem, domain, developerName)

			case "Always Trust Domain":
				await this.setDomainPolicy(domain, PinningPolicy.ALLOW)
				return this.pinKey(toolId, publicKeyPem, domain, developerName)

			case "Always Reject Domain":
				await this.setDomainPolicy(domain, PinningPolicy.DENY)
				throw new SchemaPinError(
					SchemaPinErrorType.USER_REJECTED,
					`User rejected key for ${toolId} and blocked domain ${domain}`,
				)

			case "Reject":
			default:
				throw new SchemaPinError(SchemaPinErrorType.USER_REJECTED, `User rejected key for ${toolId}`)
		}
	}

	/**
	 * Ensure the manager is initialized
	 */
	private ensureInitialized(): void {
		if (!this.isInitialized) {
			throw new SchemaPinError(SchemaPinErrorType.CONFIGURATION_ERROR, "Key pinning manager is not initialized")
		}
	}
}
