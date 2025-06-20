/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Core network security utilities for MCP servers.
 * Provides TLS enforcement, certificate validation, and secure communication protocols.
 */

import * as https from "https"
import * as crypto from "crypto"
import { z } from "zod"
import { SecurityLevel } from "./validationSchemas"

/**
 * Network security policy configuration
 */
export interface NetworkSecurityPolicy {
	/** Enforce TLS for all network communications */
	enforceTLS: boolean
	/** Minimum TLS version (1.2 or 1.3) */
	minTLSVersion: "TLSv1.2" | "TLSv1.3"
	/** Enable certificate validation */
	validateCertificates: boolean
	/** Enable certificate pinning */
	enableCertificatePinning: boolean
	/** Allowed cipher suites */
	allowedCipherSuites: string[]
	/** Connection timeout in milliseconds */
	connectionTimeout: number
	/** Request timeout in milliseconds */
	requestTimeout: number
	/** Maximum redirects to follow */
	maxRedirects: number
	/** Enable HSTS enforcement */
	enforceHSTS: boolean
	/** Custom CA certificates */
	customCACerts?: string[]
}

/**
 * Certificate pinning configuration
 */
export interface CertificatePinConfig {
	/** Domain to pin certificate for */
	domain: string
	/** SHA-256 hash of the certificate */
	sha256Hash: string
	/** Expiration date of the pin */
	expiresAt?: number
	/** Whether this is a backup pin */
	isBackup?: boolean
}

/**
 * Network security violation types
 */
export enum NetworkSecurityViolation {
	INSECURE_PROTOCOL = "insecure_protocol",
	CERTIFICATE_VALIDATION_FAILED = "certificate_validation_failed",
	CERTIFICATE_PIN_MISMATCH = "certificate_pin_mismatch",
	UNSUPPORTED_TLS_VERSION = "unsupported_tls_version",
	WEAK_CIPHER_SUITE = "weak_cipher_suite",
	CONNECTION_TIMEOUT = "connection_timeout",
	INVALID_DOMAIN = "invalid_domain",
	HSTS_VIOLATION = "hsts_violation",
}

/**
 * Network security validation result
 */
export interface NetworkSecurityResult {
	allowed: boolean
	violations: NetworkSecurityViolation[]
	warnings: string[]
	securityLevel: "low" | "medium" | "high"
	recommendations: string[]
	certificateInfo?: {
		subject: string
		issuer: string
		validFrom: Date
		validTo: Date
		fingerprint: string
	}
}

/**
 * Zod schemas for validation
 */
export const NetworkSecurityPolicySchema = z.object({
	enforceTLS: z.boolean().default(true),
	minTLSVersion: z.enum(["TLSv1.2", "TLSv1.3"]).default("TLSv1.2"),
	validateCertificates: z.boolean().default(true),
	enableCertificatePinning: z.boolean().default(false),
	allowedCipherSuites: z
		.array(z.string())
		.default([
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			"TLS_AES_128_GCM_SHA256",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES128-GCM-SHA256",
		]),
	connectionTimeout: z.number().min(1000).max(60000).default(10000),
	requestTimeout: z.number().min(1000).max(300000).default(30000),
	maxRedirects: z.number().min(0).max(10).default(3),
	enforceHSTS: z.boolean().default(true),
	customCACerts: z.array(z.string()).optional(),
})

export const CertificatePinConfigSchema = z.object({
	domain: z.string().min(1),
	sha256Hash: z.string().regex(/^[a-fA-F0-9]{64}$/),
	expiresAt: z.number().optional(),
	isBackup: z.boolean().default(false),
})

/**
 * Default network security policy
 */
export const DEFAULT_NETWORK_SECURITY_POLICY: NetworkSecurityPolicy = {
	enforceTLS: true,
	minTLSVersion: "TLSv1.2",
	validateCertificates: true,
	enableCertificatePinning: false,
	allowedCipherSuites: [
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_AES_128_GCM_SHA256",
		"ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES128-GCM-SHA256",
	],
	connectionTimeout: 10000,
	requestTimeout: 30000,
	maxRedirects: 3,
	enforceHSTS: true,
}

/**
 * Network security manager class
 */
export class NetworkSecurityManager {
	private policy: NetworkSecurityPolicy
	private certificatePins: Map<string, CertificatePinConfig[]> = new Map()
	private hstsCache: Map<
		string,
		{ maxAge: number; includeSubDomains: boolean; preload: boolean; timestamp: number }
	> = new Map()

	constructor(policy: NetworkSecurityPolicy = DEFAULT_NETWORK_SECURITY_POLICY) {
		this.policy = policy
	}

	/**
	 * Update network security policy
	 */
	updatePolicy(updates: Partial<NetworkSecurityPolicy>): void {
		this.policy = { ...this.policy, ...updates }
	}

	/**
	 * Get current network security policy
	 */
	getPolicy(): NetworkSecurityPolicy {
		return { ...this.policy }
	}

	/**
	 * Add certificate pin for a domain
	 */
	addCertificatePin(config: CertificatePinConfig): void {
		const domain = config.domain.toLowerCase()
		const pins = this.certificatePins.get(domain) || []
		pins.push(config)
		this.certificatePins.set(domain, pins)
	}

	/**
	 * Remove certificate pin for a domain
	 */
	removeCertificatePin(domain: string, sha256Hash: string): boolean {
		const pins = this.certificatePins.get(domain.toLowerCase())
		if (!pins) return false

		const index = pins.findIndex((pin) => pin.sha256Hash === sha256Hash)
		if (index === -1) return false

		pins.splice(index, 1)
		if (pins.length === 0) {
			this.certificatePins.delete(domain.toLowerCase())
		}
		return true
	}

	/**
	 * Validate URL for network security compliance
	 */
	validateURL(url: string): NetworkSecurityResult {
		const violations: NetworkSecurityViolation[] = []
		const warnings: string[] = []
		const recommendations: string[] = []

		try {
			const parsedURL = new URL(url)

			// Check protocol security
			if (this.policy.enforceTLS && parsedURL.protocol !== "https:") {
				violations.push(NetworkSecurityViolation.INSECURE_PROTOCOL)
				recommendations.push("Use HTTPS instead of HTTP for secure communication")
			}

			// Check HSTS compliance
			if (this.policy.enforceHSTS && parsedURL.protocol === "https:") {
				const hstsInfo = this.hstsCache.get(parsedURL.hostname)
				if (!hstsInfo || Date.now() - hstsInfo.timestamp > hstsInfo.maxAge * 1000) {
					warnings.push("HSTS policy not cached or expired")
					recommendations.push("Verify HSTS headers are properly configured")
				}
			}

			// Determine security level
			let securityLevel: "low" | "medium" | "high" = "high"
			if (violations.length > 0) {
				securityLevel = "low"
			} else if (warnings.length > 0) {
				securityLevel = "medium"
			}

			return {
				allowed: violations.length === 0,
				violations,
				warnings,
				securityLevel,
				recommendations,
			}
		} catch (error) {
			violations.push(NetworkSecurityViolation.INVALID_DOMAIN)
			return {
				allowed: false,
				violations,
				warnings,
				securityLevel: "low",
				recommendations: ["Provide a valid URL"],
			}
		}
	}

	/**
	 * Create secure HTTPS agent with policy enforcement
	 */
	createSecureAgent(hostname?: string): https.Agent {
		const agentOptions: https.AgentOptions = {
			// TLS configuration
			secureProtocol: this.policy.minTLSVersion === "TLSv1.3" ? "TLSv1_3_method" : "TLSv1_2_method",
			ciphers: this.policy.allowedCipherSuites.join(":"),

			// Certificate validation
			rejectUnauthorized: this.policy.validateCertificates,

			// Connection settings
			timeout: this.policy.connectionTimeout,
			keepAlive: false, // Disable keep-alive for security
			maxSockets: 1, // Limit concurrent connections
		}

		// Add custom CA certificates if provided
		if (this.policy.customCACerts && this.policy.customCACerts.length > 0) {
			agentOptions.ca = this.policy.customCACerts
		}

		// Certificate pinning validation
		if (this.policy.enableCertificatePinning && hostname) {
			agentOptions.checkServerIdentity = (host: string, cert: any) => {
				// First perform standard certificate validation
				const standardCheck = https.globalAgent.options.checkServerIdentity?.(host, cert)
				if (standardCheck) return standardCheck

				// Then check certificate pinning
				return this.validateCertificatePin(host, cert)
			}
		}

		return new https.Agent(agentOptions)
	}

	/**
	 * Validate certificate pinning
	 */
	private validateCertificatePin(hostname: string, cert: any): Error | undefined {
		const pins = this.certificatePins.get(hostname.toLowerCase())
		if (!pins || pins.length === 0) {
			// No pins configured for this domain
			return undefined
		}

		// Calculate certificate fingerprint
		const certDER = cert.raw
		const fingerprint = crypto.createHash("sha256").update(certDER).digest("hex")

		// Check if certificate matches any pin
		const now = Date.now()
		const validPins = pins.filter((pin) => !pin.expiresAt || pin.expiresAt > now)

		if (validPins.length === 0) {
			return new Error("All certificate pins have expired")
		}

		const matchingPin = validPins.find((pin) => pin.sha256Hash.toLowerCase() === fingerprint.toLowerCase())
		if (!matchingPin) {
			return new Error(`Certificate pin validation failed for ${hostname}`)
		}

		return undefined
	}

	/**
	 * Process HSTS headers
	 */
	processHSTSHeaders(hostname: string, headers: Record<string, string>): void {
		const hstsHeader = headers["strict-transport-security"]
		if (!hstsHeader) return

		const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/)
		if (!maxAgeMatch) return

		const maxAge = parseInt(maxAgeMatch[1], 10)
		const includeSubDomains = hstsHeader.includes("includeSubDomains")
		const preload = hstsHeader.includes("preload")

		this.hstsCache.set(hostname.toLowerCase(), {
			maxAge,
			includeSubDomains,
			preload,
			timestamp: Date.now(),
		})
	}

	/**
	 * Validate cipher suite
	 */
	validateCipherSuite(cipherSuite: string): boolean {
		return this.policy.allowedCipherSuites.includes(cipherSuite)
	}

	/**
	 * Get certificate information from a connection
	 */
	getCertificateInfo(cert: any): {
		subject: string
		issuer: string
		validFrom: Date
		validTo: Date
		fingerprint: string
	} {
		const certDER = cert.raw
		const fingerprint = crypto.createHash("sha256").update(certDER).digest("hex")

		return {
			subject: cert.subject?.CN || "Unknown",
			issuer: cert.issuer?.CN || "Unknown",
			validFrom: new Date(cert.valid_from),
			validTo: new Date(cert.valid_to),
			fingerprint,
		}
	}

	/**
	 * Clean up expired HSTS entries
	 */
	cleanupExpiredHSTS(): number {
		const now = Date.now()
		let cleanedCount = 0

		for (const [hostname, hstsInfo] of this.hstsCache.entries()) {
			if (now - hstsInfo.timestamp > hstsInfo.maxAge * 1000) {
				this.hstsCache.delete(hostname)
				cleanedCount++
			}
		}

		return cleanedCount
	}

	/**
	 * Clean up expired certificate pins
	 */
	cleanupExpiredPins(): number {
		const now = Date.now()
		let cleanedCount = 0

		for (const [domain, pins] of this.certificatePins.entries()) {
			const validPins = pins.filter((pin) => !pin.expiresAt || pin.expiresAt > now)
			const expiredCount = pins.length - validPins.length

			if (expiredCount > 0) {
				cleanedCount += expiredCount
				if (validPins.length === 0) {
					this.certificatePins.delete(domain)
				} else {
					this.certificatePins.set(domain, validPins)
				}
			}
		}

		return cleanedCount
	}

	/**
	 * Get network security metrics
	 */
	getMetrics(): {
		totalPinnedDomains: number
		totalPins: number
		hstsEntries: number
		expiredPins: number
		expiredHSTS: number
	} {
		const now = Date.now()
		let totalPins = 0
		let expiredPins = 0

		for (const pins of this.certificatePins.values()) {
			totalPins += pins.length
			expiredPins += pins.filter((pin) => pin.expiresAt && pin.expiresAt <= now).length
		}

		const expiredHSTS = Array.from(this.hstsCache.values()).filter(
			(hstsInfo) => now - hstsInfo.timestamp > hstsInfo.maxAge * 1000,
		).length

		return {
			totalPinnedDomains: this.certificatePins.size,
			totalPins,
			hstsEntries: this.hstsCache.size,
			expiredPins,
			expiredHSTS,
		}
	}
}

/**
 * Global network security manager instance
 */
let globalNetworkSecurityManager: NetworkSecurityManager | null = null

/**
 * Get or create the global network security manager
 */
export function getNetworkSecurityManager(policy?: NetworkSecurityPolicy): NetworkSecurityManager {
	if (!globalNetworkSecurityManager) {
		globalNetworkSecurityManager = new NetworkSecurityManager(policy)
	} else if (policy) {
		globalNetworkSecurityManager.updatePolicy(policy)
	}
	return globalNetworkSecurityManager
}

/**
 * Validate network security for a URL
 */
export function validateNetworkSecurity(url: string, policy?: NetworkSecurityPolicy): NetworkSecurityResult {
	const manager = getNetworkSecurityManager(policy)
	return manager.validateURL(url)
}

/**
 * Create a secure HTTPS agent for network requests
 */
export function createSecureHTTPSAgent(hostname?: string, policy?: NetworkSecurityPolicy): https.Agent {
	const manager = getNetworkSecurityManager(policy)
	return manager.createSecureAgent(hostname)
}
