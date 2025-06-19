/**
 * TypeScript interfaces and types for SchemaPin integration
 */

import { z } from "zod"

/**
 * Schema for SchemaPin configuration
 */
export const SchemaPinConfigSchema = z.object({
	enabled: z.boolean().default(true),
	dbPath: z.string().optional(),
	pinningMode: z.enum(["automatic", "interactive", "strict"]).default("interactive"),
	timeout: z.number().min(1000).max(30000).default(10000),
	autoPin: z.boolean().default(false),
	verifyOnToolCall: z.boolean().default(true),
})

export type SchemaPinConfig = z.infer<typeof SchemaPinConfigSchema>

/**
 * Pinning modes for key management
 */
export enum PinningMode {
	AUTOMATIC = "automatic",
	INTERACTIVE = "interactive",
	STRICT = "strict",
}

/**
 * Pinning policies for domain-level configuration
 */
export enum PinningPolicy {
	ALLOW = "allow",
	DENY = "deny",
	PROMPT = "prompt",
}

/**
 * Information about a pinned key
 */
export interface PinnedKeyInfo {
	toolId: string
	publicKeyPem: string
	domain: string
	developerName?: string
	pinnedAt: Date
	lastVerified?: Date
	fingerprint: string
}

/**
 * Result of schema verification
 */
export interface VerificationResult {
	valid: boolean
	pinned: boolean
	firstUse: boolean
	error?: string
	developerInfo?: DeveloperInfo
	keyFingerprint?: string
}

/**
 * Developer information from .well-known endpoint
 */
export interface DeveloperInfo {
	developerName: string
	contact?: string
	schemaVersion: string
	publicKeyPem: string
	revokedKeys: string[]
}

/**
 * Well-known SchemaPin response structure
 */
export interface WellKnownResponse {
	schema_version: string
	developer_name: string
	public_key_pem: string
	revoked_keys: string[]
	contact?: string
}

/**
 * Signed schema structure
 */
export interface SignedSchema {
	schema: Record<string, unknown>
	signature: string
	metadata: {
		toolId: string
		domain: string
		developer?: string
		signedAt?: string
	}
}

/**
 * Schema verification request
 */
export interface VerificationRequest {
	schema: Record<string, unknown>
	signature: string
	toolId: string
	domain: string
	autoPin?: boolean
}

/**
 * Key pinning prompt response
 */
export interface PinningPromptResponse {
	shouldPin: boolean
	reason?: string
}

/**
 * Error types for SchemaPin operations
 */
export enum SchemaPinErrorType {
	INVALID_SIGNATURE = "invalid_signature",
	KEY_REVOKED = "key_revoked",
	KEY_NOT_FOUND = "key_not_found",
	NETWORK_ERROR = "network_error",
	PARSING_ERROR = "parsing_error",
	CONFIGURATION_ERROR = "configuration_error",
	DATABASE_ERROR = "database_error",
	USER_REJECTED = "user_rejected",
}

/**
 * SchemaPin specific error class
 */
export class SchemaPinError extends Error {
	constructor(
		public type: SchemaPinErrorType,
		message: string,
		public details?: Record<string, unknown>,
	) {
		super(message)
		this.name = "SchemaPinError"
	}
}

/**
 * Events emitted by SchemaPin services
 */
export interface SchemaPinEventMap {
	keyPinned: { toolId: string; domain: string; fingerprint: string }
	keyRevoked: { toolId: string; domain: string; fingerprint: string }
	verificationSuccess: { toolId: string; domain: string; firstUse: boolean }
	verificationFailure: { toolId: string; domain: string; error: string }
	configurationChanged: { config: SchemaPinConfig }
}

/**
 * Configuration for public key discovery
 */
export interface DiscoveryConfig {
	timeout: number
	retries: number
	userAgent: string
}

/**
 * MCP tool schema verification context
 */
export interface McpToolVerificationContext {
	serverName: string
	toolName: string
	schema: Record<string, unknown>
	signature?: string
	domain?: string
	toolId?: string
}
