/**
 * Main SchemaPin service interface for RooCode MCP integration
 */

import * as vscode from "vscode"
import { EventEmitter } from "events"
import {
	SchemaPinConfig,
	SchemaPinConfigSchema,
	VerificationResult,
	VerificationRequest,
	PinnedKeyInfo,
	SchemaPinError,
	SchemaPinErrorType,
	SchemaPinEventMap,
	McpToolVerificationContext,
} from "./types"
import { SchemaPinValidator } from "./SchemaPinValidator"
import { KeyPinningManager } from "./KeyPinningManager"

/**
 * Main service class for SchemaPin integration with RooCode
 * Provides schema verification and key pinning functionality for MCP tools
 */
export class SchemaPinService extends EventEmitter {
	private validator: SchemaPinValidator
	private keyManager: KeyPinningManager
	private config: SchemaPinConfig
	private disposables: vscode.Disposable[] = []
	private isInitialized = false

	constructor(
		private context: vscode.ExtensionContext,
		config?: Partial<SchemaPinConfig>,
	) {
		super()
		this.config = this.validateConfig(config)
		this.validator = new SchemaPinValidator(this.config)
		this.keyManager = new KeyPinningManager(this.context, this.config)

		this.setupEventHandlers()
	}

	/**
	 * Initialize the SchemaPin service
	 */
	async initialize(): Promise<void> {
		if (this.isInitialized) {
			return
		}

		try {
			await this.keyManager.initialize()
			await this.validator.initialize()

			this.isInitialized = true
			// Service initialized successfully
		} catch (error) {
			throw new SchemaPinError(
				SchemaPinErrorType.CONFIGURATION_ERROR,
				`Failed to initialize SchemaPin service: ${error instanceof Error ? error.message : String(error)}`,
				{ originalError: error },
			)
		}
	}

	/**
	 * Verify a schema signature and handle key pinning
	 */
	async verifySchema(request: VerificationRequest): Promise<VerificationResult> {
		this.ensureInitialized()

		try {
			const result = await this.validator.verifySchema(request)

			// Emit appropriate events
			if (result.valid) {
				this.emit("verificationSuccess", {
					toolId: request.toolId,
					domain: request.domain,
					firstUse: result.firstUse,
				})
			} else {
				this.emit("verificationFailure", {
					toolId: request.toolId,
					domain: request.domain,
					error: result.error || "Unknown verification error",
				})
			}

			return result
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : String(error)
			this.emit("verificationFailure", {
				toolId: request.toolId,
				domain: request.domain,
				error: errorMessage,
			})
			throw error
		}
	}

	/**
	 * Verify an MCP tool schema in the context of RooCode's MCP system
	 */
	async verifyMcpTool(context: McpToolVerificationContext): Promise<VerificationResult> {
		// Extract or derive the necessary information for verification
		const toolId = context.toolId || `${context.domain || context.serverName}/${context.toolName}`
		const domain = context.domain || this.extractDomainFromServerName(context.serverName)

		if (!context.signature) {
			// If no signature is provided, check if verification is required
			if (this.config.verifyOnToolCall) {
				return {
					valid: false,
					pinned: false,
					firstUse: false,
					error: "No signature provided for MCP tool verification",
				}
			} else {
				// Skip verification if not required
				return {
					valid: true,
					pinned: false,
					firstUse: false,
				}
			}
		}

		const request: VerificationRequest = {
			schema: context.schema,
			signature: context.signature,
			toolId,
			domain,
			autoPin: this.config.autoPin,
		}

		return this.verifySchema(request)
	}

	/**
	 * Get information about a pinned key
	 */
	async getPinnedKeyInfo(toolId: string): Promise<PinnedKeyInfo | null> {
		this.ensureInitialized()
		return this.keyManager.getPinnedKeyInfo(toolId)
	}

	/**
	 * List all pinned keys
	 */
	async listPinnedKeys(): Promise<PinnedKeyInfo[]> {
		this.ensureInitialized()
		return this.keyManager.listPinnedKeys()
	}

	/**
	 * Remove a pinned key
	 */
	async removePinnedKey(toolId: string): Promise<boolean> {
		this.ensureInitialized()
		const result = await this.keyManager.removePinnedKey(toolId)

		if (result) {
			// Find the key info before removal for the event
			const keyInfo = await this.keyManager.getPinnedKeyInfo(toolId)
			if (keyInfo) {
				this.emit("keyRevoked", {
					toolId,
					domain: keyInfo.domain,
					fingerprint: keyInfo.fingerprint,
				})
			}
		}

		return result
	}

	/**
	 * Update the service configuration
	 */
	async updateConfig(newConfig: Partial<SchemaPinConfig>): Promise<void> {
		const updatedConfig = this.validateConfig({ ...this.config, ...newConfig })

		// Update components with new configuration
		await this.validator.updateConfig(updatedConfig)
		await this.keyManager.updateConfig(updatedConfig)

		this.config = updatedConfig
		this.emit("configurationChanged", { config: this.config })
	}

	/**
	 * Get current configuration
	 */
	getConfig(): SchemaPinConfig {
		return { ...this.config }
	}

	/**
	 * Check if the service is enabled
	 */
	isEnabled(): boolean {
		return this.config.enabled
	}

	/**
	 * Dispose of the service and clean up resources
	 */
	async dispose(): Promise<void> {
		this.disposables.forEach((d) => d.dispose())
		this.disposables = []

		await this.validator.dispose()
		await this.keyManager.dispose()

		this.removeAllListeners()
		this.isInitialized = false
	}

	/**
	 * Validate and normalize configuration
	 */
	private validateConfig(config?: Partial<SchemaPinConfig>): SchemaPinConfig {
		try {
			return SchemaPinConfigSchema.parse(config || {})
		} catch (error) {
			throw new SchemaPinError(
				SchemaPinErrorType.CONFIGURATION_ERROR,
				`Invalid SchemaPin configuration: ${error instanceof Error ? error.message : String(error)}`,
				{ config, validationError: error },
			)
		}
	}

	/**
	 * Set up event handlers for internal components
	 */
	private setupEventHandlers(): void {
		// Forward key manager events
		this.keyManager.on("keyPinned", (data: any) => {
			this.emit("keyPinned", data)
		})

		this.keyManager.on("keyRevoked", (data: any) => {
			this.emit("keyRevoked", data)
		})

		// Handle validator events
		this.validator.on("verificationAttempt", (data: any) => {
			// Log verification attempts for debugging
			console.log(`SchemaPin verification attempt for ${data.toolId}@${data.domain}`)
		})
	}

	/**
	 * Extract domain from MCP server name
	 */
	private extractDomainFromServerName(serverName: string): string {
		// Try to extract domain from server name
		// This is a heuristic approach - in practice, servers should provide explicit domain info
		const urlMatch = serverName.match(/https?:\/\/([^\/]+)/)
		if (urlMatch) {
			return urlMatch[1]
		}

		// Check if it looks like a domain
		if (serverName.includes(".") && !serverName.includes("/")) {
			return serverName
		}

		// Fallback to using the server name as domain
		return serverName
	}

	/**
	 * Ensure the service is initialized
	 */
	private ensureInitialized(): void {
		if (!this.isInitialized) {
			throw new SchemaPinError(
				SchemaPinErrorType.CONFIGURATION_ERROR,
				"SchemaPin service is not initialized. Call initialize() first.",
			)
		}
	}

	/**
	 * Type-safe event emitter methods
	 */
	override emit<K extends keyof SchemaPinEventMap>(event: K, data: SchemaPinEventMap[K]): boolean {
		return super.emit(event, data)
	}

	override on<K extends keyof SchemaPinEventMap>(event: K, listener: (data: SchemaPinEventMap[K]) => void): this {
		return super.on(event, listener)
	}

	override once<K extends keyof SchemaPinEventMap>(event: K, listener: (data: SchemaPinEventMap[K]) => void): this {
		return super.once(event, listener)
	}

	override off<K extends keyof SchemaPinEventMap>(event: K, listener: (data: SchemaPinEventMap[K]) => void): this {
		return super.off(event, listener)
	}
}
