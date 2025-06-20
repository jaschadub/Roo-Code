/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Authentication manager for MCP network security.
 * Provides API key validation, token management, and multi-method authentication.
 */

import * as crypto from "crypto"
import { z } from "zod"

/**
 * Authentication method types
 */
export enum AuthenticationMethod {
	API_KEY = "api_key",
	BEARER_TOKEN = "bearer_token",
	BASIC_AUTH = "basic_auth",
	OAUTH2 = "oauth2",
	CUSTOM_HEADER = "custom_header",
	MUTUAL_TLS = "mutual_tls",
}

/**
 * API key configuration
 */
export interface APIKeyConfig {
	id: string
	name: string
	key: string
	hashedKey: string
	algorithm: "sha256" | "sha512"
	salt: string
	createdAt: number
	expiresAt?: number
	lastUsedAt?: number
	usageCount: number
	permissions: string[]
	rateLimit: {
		requestsPerMinute: number
		requestsPerHour: number
		requestsPerDay: number
	}
	ipWhitelist?: string[]
	userAgent?: string
	description?: string
	active: boolean
}

/**
 * Authentication token
 */
export interface AuthenticationToken {
	id: string
	type: AuthenticationMethod
	value: string
	hashedValue: string
	createdAt: number
	expiresAt: number
	refreshToken?: string
	scope: string[]
	issuer: string
	audience: string
	subject?: string
	metadata: Record<string, any>
}

/**
 * Authentication result
 */
export interface AuthenticationResult {
	authenticated: boolean
	method: AuthenticationMethod
	keyId?: string
	tokenId?: string
	permissions: string[]
	rateLimit: {
		remaining: number
		resetTime: number
		limit: number
	}
	errors: string[]
	warnings: string[]
	metadata: Record<string, any>
}

/**
 * OAuth2 configuration
 */
export interface OAuth2Config {
	clientId: string
	clientSecret: string
	authorizationEndpoint: string
	tokenEndpoint: string
	scope: string[]
	redirectUri: string
	state?: string
	codeChallenge?: string
	codeChallengeMethod?: "S256" | "plain"
}

/**
 * Rate limiting configuration
 */
export interface RateLimitConfig {
	windowMs: number
	maxRequests: number
	skipSuccessfulRequests: boolean
	skipFailedRequests: boolean
	keyGenerator: (request: any) => string
}

/**
 * Zod schemas
 */
export const AuthenticationMethodSchema = z.nativeEnum(AuthenticationMethod)

export const APIKeyConfigSchema = z.object({
	id: z.string(),
	name: z.string(),
	key: z.string(),
	hashedKey: z.string(),
	algorithm: z.enum(["sha256", "sha512"]),
	salt: z.string(),
	createdAt: z.number(),
	expiresAt: z.number().optional(),
	lastUsedAt: z.number().optional(),
	usageCount: z.number().default(0),
	permissions: z.array(z.string()),
	rateLimit: z.object({
		requestsPerMinute: z.number().positive(),
		requestsPerHour: z.number().positive(),
		requestsPerDay: z.number().positive(),
	}),
	ipWhitelist: z.array(z.string()).optional(),
	userAgent: z.string().optional(),
	description: z.string().optional(),
	active: z.boolean().default(true),
})

export const AuthenticationTokenSchema = z.object({
	id: z.string(),
	type: AuthenticationMethodSchema,
	value: z.string(),
	hashedValue: z.string(),
	createdAt: z.number(),
	expiresAt: z.number(),
	refreshToken: z.string().optional(),
	scope: z.array(z.string()),
	issuer: z.string(),
	audience: z.string(),
	subject: z.string().optional(),
	metadata: z.record(z.any()),
})

export const OAuth2ConfigSchema = z.object({
	clientId: z.string(),
	clientSecret: z.string(),
	authorizationEndpoint: z.string().url(),
	tokenEndpoint: z.string().url(),
	scope: z.array(z.string()),
	redirectUri: z.string().url(),
	state: z.string().optional(),
	codeChallenge: z.string().optional(),
	codeChallengeMethod: z.enum(["S256", "plain"]).optional(),
})

/**
 * Authentication manager class
 */
export class AuthenticationManager {
	private apiKeys: Map<string, APIKeyConfig> = new Map()
	private tokens: Map<string, AuthenticationToken> = new Map()
	private rateLimitCounters: Map<string, { count: number; resetTime: number }> = new Map()
	private oauth2Configs: Map<string, OAuth2Config> = new Map()

	/**
	 * Generate a secure API key
	 */
	generateAPIKey(length: number = 32): string {
		return crypto.randomBytes(length).toString("hex")
	}

	/**
	 * Hash API key with salt
	 */
	private hashAPIKey(key: string, salt: string, algorithm: "sha256" | "sha512" = "sha256"): string {
		return crypto
			.createHash(algorithm)
			.update(key + salt)
			.digest("hex")
	}

	/**
	 * Generate salt for API key hashing
	 */
	private generateSalt(): string {
		return crypto.randomBytes(16).toString("hex")
	}

	/**
	 * Create new API key
	 */
	createAPIKey(config: {
		name: string
		permissions: string[]
		expiresAt?: number
		rateLimit?: {
			requestsPerMinute: number
			requestsPerHour: number
			requestsPerDay: number
		}
		ipWhitelist?: string[]
		userAgent?: string
		description?: string
	}): { keyId: string; apiKey: string } {
		const keyId = crypto.randomUUID()
		const apiKey = this.generateAPIKey()
		const salt = this.generateSalt()
		const hashedKey = this.hashAPIKey(apiKey, salt)

		const keyConfig: APIKeyConfig = {
			id: keyId,
			name: config.name,
			key: apiKey,
			hashedKey,
			algorithm: "sha256",
			salt,
			createdAt: Date.now(),
			expiresAt: config.expiresAt,
			usageCount: 0,
			permissions: config.permissions,
			rateLimit: config.rateLimit || {
				requestsPerMinute: 60,
				requestsPerHour: 1000,
				requestsPerDay: 10000,
			},
			ipWhitelist: config.ipWhitelist,
			userAgent: config.userAgent,
			description: config.description,
			active: true,
		}

		this.apiKeys.set(keyId, keyConfig)
		return { keyId, apiKey }
	}

	/**
	 * Validate API key
	 */
	validateAPIKey(
		apiKey: string,
		context: {
			ipAddress?: string
			userAgent?: string
			timestamp?: number
		} = {},
	): AuthenticationResult {
		const timestamp = context.timestamp || Date.now()
		const errors: string[] = []
		const warnings: string[] = []

		// Find matching API key
		let matchingKey: APIKeyConfig | undefined
		for (const keyConfig of this.apiKeys.values()) {
			if (!keyConfig.active) continue

			const hashedInput = this.hashAPIKey(apiKey, keyConfig.salt, keyConfig.algorithm)
			if (hashedInput === keyConfig.hashedKey) {
				matchingKey = keyConfig
				break
			}
		}

		if (!matchingKey) {
			errors.push("Invalid API key")
			return {
				authenticated: false,
				method: AuthenticationMethod.API_KEY,
				permissions: [],
				rateLimit: { remaining: 0, resetTime: 0, limit: 0 },
				errors,
				warnings,
				metadata: {},
			}
		}

		// Check expiration
		if (matchingKey.expiresAt && timestamp > matchingKey.expiresAt) {
			errors.push("API key has expired")
			return {
				authenticated: false,
				method: AuthenticationMethod.API_KEY,
				keyId: matchingKey.id,
				permissions: [],
				rateLimit: { remaining: 0, resetTime: 0, limit: 0 },
				errors,
				warnings,
				metadata: {},
			}
		}

		// Check IP whitelist
		if (matchingKey.ipWhitelist && context.ipAddress) {
			if (!matchingKey.ipWhitelist.includes(context.ipAddress)) {
				errors.push("IP address not whitelisted")
				return {
					authenticated: false,
					method: AuthenticationMethod.API_KEY,
					keyId: matchingKey.id,
					permissions: [],
					rateLimit: { remaining: 0, resetTime: 0, limit: 0 },
					errors,
					warnings,
					metadata: {},
				}
			}
		}

		// Check User-Agent
		if (matchingKey.userAgent && context.userAgent) {
			if (matchingKey.userAgent !== context.userAgent) {
				warnings.push("User-Agent mismatch")
			}
		}

		// Check rate limits
		const rateLimitResult = this.checkRateLimit(matchingKey.id, matchingKey.rateLimit, timestamp)
		if (!rateLimitResult.allowed) {
			errors.push("Rate limit exceeded")
			return {
				authenticated: false,
				method: AuthenticationMethod.API_KEY,
				keyId: matchingKey.id,
				permissions: matchingKey.permissions,
				rateLimit: rateLimitResult,
				errors,
				warnings,
				metadata: {},
			}
		}

		// Update usage statistics
		matchingKey.usageCount++
		matchingKey.lastUsedAt = timestamp

		return {
			authenticated: true,
			method: AuthenticationMethod.API_KEY,
			keyId: matchingKey.id,
			permissions: matchingKey.permissions,
			rateLimit: rateLimitResult,
			errors,
			warnings,
			metadata: {
				keyName: matchingKey.name,
				usageCount: matchingKey.usageCount,
			},
		}
	}

	/**
	 * Check rate limits
	 */
	private checkRateLimit(
		keyId: string,
		limits: APIKeyConfig["rateLimit"],
		timestamp: number,
	): {
		allowed: boolean
		remaining: number
		resetTime: number
		limit: number
	} {
		const minuteKey = `${keyId}:minute:${Math.floor(timestamp / 60000)}`
		const hourKey = `${keyId}:hour:${Math.floor(timestamp / 3600000)}`
		const dayKey = `${keyId}:day:${Math.floor(timestamp / 86400000)}`

		// Check minute limit
		const minuteCounter = this.rateLimitCounters.get(minuteKey) || {
			count: 0,
			resetTime: Math.floor(timestamp / 60000) * 60000 + 60000,
		}
		if (minuteCounter.count >= limits.requestsPerMinute) {
			return {
				allowed: false,
				remaining: 0,
				resetTime: minuteCounter.resetTime,
				limit: limits.requestsPerMinute,
			}
		}

		// Check hour limit
		const hourCounter = this.rateLimitCounters.get(hourKey) || {
			count: 0,
			resetTime: Math.floor(timestamp / 3600000) * 3600000 + 3600000,
		}
		if (hourCounter.count >= limits.requestsPerHour) {
			return {
				allowed: false,
				remaining: 0,
				resetTime: hourCounter.resetTime,
				limit: limits.requestsPerHour,
			}
		}

		// Check day limit
		const dayCounter = this.rateLimitCounters.get(dayKey) || {
			count: 0,
			resetTime: Math.floor(timestamp / 86400000) * 86400000 + 86400000,
		}
		if (dayCounter.count >= limits.requestsPerDay) {
			return {
				allowed: false,
				remaining: 0,
				resetTime: dayCounter.resetTime,
				limit: limits.requestsPerDay,
			}
		}

		// Increment counters
		minuteCounter.count++
		hourCounter.count++
		dayCounter.count++

		this.rateLimitCounters.set(minuteKey, minuteCounter)
		this.rateLimitCounters.set(hourKey, hourCounter)
		this.rateLimitCounters.set(dayKey, dayCounter)

		return {
			allowed: true,
			remaining: Math.min(
				limits.requestsPerMinute - minuteCounter.count,
				limits.requestsPerHour - hourCounter.count,
				limits.requestsPerDay - dayCounter.count,
			),
			resetTime: Math.min(minuteCounter.resetTime, hourCounter.resetTime, dayCounter.resetTime),
			limit: limits.requestsPerMinute,
		}
	}

	/**
	 * Validate Bearer token
	 */
	validateBearerToken(token: string, timestamp: number = Date.now()): AuthenticationResult {
		const errors: string[] = []
		const warnings: string[] = []

		// Find matching token
		const matchingToken = Array.from(this.tokens.values()).find(
			(t) => t.type === AuthenticationMethod.BEARER_TOKEN && t.value === token,
		)

		if (!matchingToken) {
			errors.push("Invalid bearer token")
			return {
				authenticated: false,
				method: AuthenticationMethod.BEARER_TOKEN,
				permissions: [],
				rateLimit: { remaining: 0, resetTime: 0, limit: 0 },
				errors,
				warnings,
				metadata: {},
			}
		}

		// Check expiration
		if (timestamp > matchingToken.expiresAt) {
			errors.push("Bearer token has expired")
			return {
				authenticated: false,
				method: AuthenticationMethod.BEARER_TOKEN,
				tokenId: matchingToken.id,
				permissions: [],
				rateLimit: { remaining: 0, resetTime: 0, limit: 0 },
				errors,
				warnings,
				metadata: {},
			}
		}

		return {
			authenticated: true,
			method: AuthenticationMethod.BEARER_TOKEN,
			tokenId: matchingToken.id,
			permissions: matchingToken.scope,
			rateLimit: { remaining: 1000, resetTime: timestamp + 3600000, limit: 1000 },
			errors,
			warnings,
			metadata: {
				issuer: matchingToken.issuer,
				audience: matchingToken.audience,
				subject: matchingToken.subject,
			},
		}
	}

	/**
	 * Revoke API key
	 */
	revokeAPIKey(keyId: string): boolean {
		const keyConfig = this.apiKeys.get(keyId)
		if (!keyConfig) return false

		keyConfig.active = false
		return true
	}

	/**
	 * Delete API key
	 */
	deleteAPIKey(keyId: string): boolean {
		return this.apiKeys.delete(keyId)
	}

	/**
	 * List API keys
	 */
	listAPIKeys(): Array<Omit<APIKeyConfig, "key" | "hashedKey" | "salt">> {
		return Array.from(this.apiKeys.values()).map((key) => {
			const { key: _, hashedKey: __, salt: ___, ...safeKey } = key
			return safeKey
		})
	}

	/**
	 * Rotate API key
	 */
	rotateAPIKey(keyId: string): { apiKey: string } | null {
		const keyConfig = this.apiKeys.get(keyId)
		if (!keyConfig) return null

		const newApiKey = this.generateAPIKey()
		const newSalt = this.generateSalt()
		const newHashedKey = this.hashAPIKey(newApiKey, newSalt)

		keyConfig.key = newApiKey
		keyConfig.hashedKey = newHashedKey
		keyConfig.salt = newSalt
		keyConfig.usageCount = 0
		keyConfig.lastUsedAt = undefined

		return { apiKey: newApiKey }
	}

	/**
	 * Clean up expired rate limit counters
	 */
	cleanupRateLimitCounters(): number {
		const now = Date.now()
		let cleanedCount = 0

		for (const [key, counter] of this.rateLimitCounters.entries()) {
			if (now > counter.resetTime) {
				this.rateLimitCounters.delete(key)
				cleanedCount++
			}
		}

		return cleanedCount
	}

	/**
	 * Clean up expired tokens
	 */
	cleanupExpiredTokens(): number {
		const now = Date.now()
		let cleanedCount = 0

		for (const [id, token] of this.tokens.entries()) {
			if (now > token.expiresAt) {
				this.tokens.delete(id)
				cleanedCount++
			}
		}

		return cleanedCount
	}

	/**
	 * Get authentication metrics
	 */
	getMetrics(): {
		totalAPIKeys: number
		activeAPIKeys: number
		totalTokens: number
		rateLimitCounters: number
		oauth2Configs: number
	} {
		const activeAPIKeys = Array.from(this.apiKeys.values()).filter((key) => key.active).length

		return {
			totalAPIKeys: this.apiKeys.size,
			activeAPIKeys,
			totalTokens: this.tokens.size,
			rateLimitCounters: this.rateLimitCounters.size,
			oauth2Configs: this.oauth2Configs.size,
		}
	}
}

/**
 * Global authentication manager instance
 */
let globalAuthenticationManager: AuthenticationManager | null = null

/**
 * Get or create the global authentication manager
 */
export function getAuthenticationManager(): AuthenticationManager {
	if (!globalAuthenticationManager) {
		globalAuthenticationManager = new AuthenticationManager()
	}
	return globalAuthenticationManager
}
