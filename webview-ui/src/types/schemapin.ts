/**
 * TypeScript interfaces for SchemaPin UI components
 * These are simplified versions of the types from the extension
 */

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
 * Key pinning prompt response
 */
export interface PinningPromptResponse {
	shouldPin: boolean
	reason?: string
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
 * Security recommendation levels
 */
export enum SecurityRecommendation {
	TRUST = "trust",
	CAUTION = "caution",
	REJECT = "reject",
}
