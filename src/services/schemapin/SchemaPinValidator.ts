/**
 * Schema validation logic using SchemaPin library
 */

import { EventEmitter } from "events"
import {
	SchemaPinConfig,
	VerificationResult,
	VerificationRequest,
	DeveloperInfo,
	WellKnownResponse,
	SchemaPinError,
	SchemaPinErrorType,
} from "./types"

// Import SchemaPin library components
// Note: These imports will be available once SchemaPin is properly integrated
// For now, we'll create interfaces that match the expected SchemaPin API

interface SchemaVerificationWorkflow {
	verifySchema(
		schema: Record<string, unknown>,
		signature: string,
		toolId: string,
		domain: string,
		autoPin?: boolean,
	): Promise<{
		valid: boolean
		pinned: boolean
		first_use: boolean
		error?: string
		developer_info?: {
			developer_name: string
			contact?: string
		}
	}>
}

interface PublicKeyDiscovery {
	fetchWellKnown(domain: string): Promise<WellKnownResponse>
	getDeveloperInfo(domain: string): Promise<DeveloperInfo>
	checkKeyRevocation(publicKeyPem: string, revokedKeys: string[]): boolean
}

/**
 * Handles schema verification using the SchemaPin library
 */
export class SchemaPinValidator extends EventEmitter {
	private verificationWorkflow: SchemaVerificationWorkflow | null = null
	private publicKeyDiscovery: PublicKeyDiscovery | null = null
	private isInitialized = false

	constructor(private config: SchemaPinConfig) {
		super()
	}

	/**
	 * Initialize the validator with SchemaPin components
	 */
	async initialize(): Promise<void> {
		if (this.isInitialized) {
			return
		}

		try {
			// Initialize SchemaPin components
			// Note: This will be replaced with actual SchemaPin imports
			await this.initializeSchemaPin()

			this.isInitialized = true
		} catch (error) {
			throw new SchemaPinError(
				SchemaPinErrorType.CONFIGURATION_ERROR,
				`Failed to initialize SchemaPin validator: ${error instanceof Error ? error.message : String(error)}`,
				{ originalError: error },
			)
		}
	}

	/**
	 * Verify a schema signature
	 */
	async verifySchema(request: VerificationRequest): Promise<VerificationResult> {
		this.ensureInitialized()

		this.emit("verificationAttempt", {
			toolId: request.toolId,
			domain: request.domain,
		})

		try {
			// Use SchemaPin verification workflow
			const result = await this.performVerification(request)

			return {
				valid: result.valid,
				pinned: result.pinned,
				firstUse: result.first_use,
				error: result.error,
				developerInfo: result.developer_info
					? {
							developerName: result.developer_info.developer_name,
							contact: result.developer_info.contact,
							schemaVersion: "1.1", // Default version
							publicKeyPem: "", // Will be filled by actual implementation
							revokedKeys: [], // Will be filled by actual implementation
						}
					: undefined,
			}
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : String(error)

			// Determine error type based on the error
			let errorType = SchemaPinErrorType.INVALID_SIGNATURE
			if (errorMessage.includes("network") || errorMessage.includes("fetch")) {
				errorType = SchemaPinErrorType.NETWORK_ERROR
			} else if (errorMessage.includes("revoked")) {
				errorType = SchemaPinErrorType.KEY_REVOKED
			} else if (errorMessage.includes("not found")) {
				errorType = SchemaPinErrorType.KEY_NOT_FOUND
			}

			throw new SchemaPinError(errorType, errorMessage, {
				toolId: request.toolId,
				domain: request.domain,
				originalError: error,
			})
		}
	}

	/**
	 * Update validator configuration
	 */
	async updateConfig(newConfig: SchemaPinConfig): Promise<void> {
		this.config = newConfig

		// Reinitialize if configuration changes require it
		if (this.isInitialized) {
			await this.reinitialize()
		}
	}

	/**
	 * Dispose of the validator
	 */
	async dispose(): Promise<void> {
		this.removeAllListeners()
		this.isInitialized = false
		this.verificationWorkflow = null
		this.publicKeyDiscovery = null
	}

	/**
	 * Initialize SchemaPin library components
	 * This is a placeholder that will be replaced with actual SchemaPin integration
	 */
	private async initializeSchemaPin(): Promise<void> {
		// TODO: Replace with actual SchemaPin initialization
		// For now, create mock implementations

		this.verificationWorkflow = {
			async verifySchema(schema, signature, toolId, domain, autoPin = false) {
				// Mock implementation - will be replaced with actual SchemaPin
				return {
					valid: true,
					pinned: false,
					first_use: true,
					developer_info: {
						developer_name: "Mock Developer",
						contact: "mock@example.com",
					},
				}
			},
		}

		this.publicKeyDiscovery = {
			async fetchWellKnown(domain: string): Promise<WellKnownResponse> {
				// Mock implementation
				return {
					schema_version: "1.1",
					developer_name: "Mock Developer",
					public_key_pem: "-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----",
					revoked_keys: [],
					contact: "mock@example.com",
				}
			},

			async getDeveloperInfo(domain: string): Promise<DeveloperInfo> {
				const wellKnown = await this.fetchWellKnown(domain)
				return {
					developerName: wellKnown.developer_name,
					contact: wellKnown.contact,
					schemaVersion: wellKnown.schema_version,
					publicKeyPem: wellKnown.public_key_pem,
					revokedKeys: wellKnown.revoked_keys,
				}
			},

			checkKeyRevocation(publicKeyPem: string, revokedKeys: string[]): boolean {
				// Mock implementation - always return false (not revoked)
				return false
			},
		}
	}

	/**
	 * Perform the actual schema verification
	 */
	private async performVerification(request: VerificationRequest): Promise<{
		valid: boolean
		pinned: boolean
		first_use: boolean
		error?: string
		developer_info?: {
			developer_name: string
			contact?: string
		}
	}> {
		if (!this.verificationWorkflow) {
			throw new Error("Verification workflow not initialized")
		}

		// Check if verification is enabled
		if (!this.config.enabled) {
			return {
				valid: true,
				pinned: false,
				first_use: false,
			}
		}

		// Perform verification with timeout
		const timeoutPromise = new Promise<never>((_, reject) => {
			setTimeout(() => {
				reject(new Error(`Verification timeout after ${this.config.timeout}ms`))
			}, this.config.timeout)
		})

		const verificationPromise = this.verificationWorkflow.verifySchema(
			request.schema,
			request.signature,
			request.toolId,
			request.domain,
			request.autoPin ?? this.config.autoPin,
		)

		return Promise.race([verificationPromise, timeoutPromise])
	}

	/**
	 * Reinitialize the validator
	 */
	private async reinitialize(): Promise<void> {
		await this.dispose()
		await this.initialize()
	}

	/**
	 * Ensure the validator is initialized
	 */
	private ensureInitialized(): void {
		if (!this.isInitialized) {
			throw new SchemaPinError(SchemaPinErrorType.CONFIGURATION_ERROR, "SchemaPin validator is not initialized")
		}
	}
}
