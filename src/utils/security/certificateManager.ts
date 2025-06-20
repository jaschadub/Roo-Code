/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Certificate validation and pinning management for MCP network security.
 * Provides certificate validation, pinning, and trust management capabilities.
 */

import * as crypto from "crypto"
import * as fs from "fs/promises"
import * as path from "path"
import { z } from "zod"

/**
 * Certificate information structure
 */
export interface CertificateInfo {
	subject: string
	issuer: string
	serialNumber: string
	validFrom: Date
	validTo: Date
	fingerprint: string
	sha256Fingerprint: string
	publicKey: string
	keySize: number
	signatureAlgorithm: string
	extensions: Record<string, any>
}

/**
 * Certificate validation result
 */
export interface CertificateValidationResult {
	valid: boolean
	trusted: boolean
	expired: boolean
	selfSigned: boolean
	revoked: boolean
	chainValid: boolean
	errors: string[]
	warnings: string[]
	certificateInfo: CertificateInfo
}

/**
 * Certificate store configuration
 */
export interface CertificateStoreConfig {
	/** Path to custom CA certificates directory */
	customCAPath?: string
	/** Enable certificate revocation checking */
	enableRevocationCheck: boolean
	/** Certificate cache TTL in milliseconds */
	cacheTTL: number
	/** Maximum certificate chain length */
	maxChainLength: number
	/** Enable OCSP stapling validation */
	enableOCSPStapling: boolean
}

/**
 * Certificate pinning entry
 */
export interface CertificatePin {
	id: string
	domain: string
	subdomains: boolean
	sha256Hash: string
	backupHashes: string[]
	createdAt: number
	expiresAt?: number
	description?: string
	reportOnly: boolean
}

/**
 * Zod schemas
 */
export const CertificateInfoSchema = z.object({
	subject: z.string(),
	issuer: z.string(),
	serialNumber: z.string(),
	validFrom: z.date(),
	validTo: z.date(),
	fingerprint: z.string(),
	sha256Fingerprint: z.string(),
	publicKey: z.string(),
	keySize: z.number(),
	signatureAlgorithm: z.string(),
	extensions: z.record(z.any()),
})

export const CertificateStoreConfigSchema = z.object({
	customCAPath: z.string().optional(),
	enableRevocationCheck: z.boolean().default(true),
	cacheTTL: z.number().min(60000).max(86400000).default(3600000), // 1 hour to 24 hours
	maxChainLength: z.number().min(1).max(10).default(5),
	enableOCSPStapling: z.boolean().default(true),
})

export const CertificatePinSchema = z.object({
	id: z.string(),
	domain: z.string(),
	subdomains: z.boolean().default(false),
	sha256Hash: z.string().regex(/^[a-fA-F0-9]{64}$/),
	backupHashes: z.array(z.string().regex(/^[a-fA-F0-9]{64}$/)).default([]),
	createdAt: z.number(),
	expiresAt: z.number().optional(),
	description: z.string().optional(),
	reportOnly: z.boolean().default(false),
})

/**
 * Default certificate store configuration
 */
export const DEFAULT_CERTIFICATE_STORE_CONFIG: CertificateStoreConfig = {
	enableRevocationCheck: true,
	cacheTTL: 3600000, // 1 hour
	maxChainLength: 5,
	enableOCSPStapling: true,
}

/**
 * Certificate manager class
 */
export class CertificateManager {
	private config: CertificateStoreConfig
	private certificateCache: Map<string, { cert: CertificateInfo; timestamp: number }> = new Map()
	private pins: Map<string, CertificatePin[]> = new Map()
	private customCAs: string[] = []
	private revokedCertificates: Set<string> = new Set()

	constructor(config: CertificateStoreConfig = DEFAULT_CERTIFICATE_STORE_CONFIG) {
		this.config = config
		this.loadCustomCAs()
	}

	/**
	 * Load custom CA certificates
	 */
	private async loadCustomCAs(): Promise<void> {
		if (!this.config.customCAPath) return

		try {
			const files = await fs.readdir(this.config.customCAPath)
			const certFiles = files.filter((file) => file.endsWith(".pem") || file.endsWith(".crt"))

			for (const file of certFiles) {
				try {
					const certPath = path.join(this.config.customCAPath, file)
					const certData = await fs.readFile(certPath, "utf8")
					this.customCAs.push(certData)
				} catch (error) {
					console.warn(`Failed to load custom CA certificate ${file}:`, error)
				}
			}
		} catch (error) {
			console.warn("Failed to load custom CA certificates:", error)
		}
	}

	/**
	 * Parse certificate from PEM or DER format
	 */
	parseCertificate(certData: Buffer | string): CertificateInfo {
		// This is a simplified implementation
		// In a real implementation, you would use a proper X.509 parser
		const cert = typeof certData === "string" ? Buffer.from(certData) : certData

		// Calculate fingerprints
		const fingerprint = crypto.createHash("sha1").update(cert).digest("hex")
		const sha256Fingerprint = crypto.createHash("sha256").update(cert).digest("hex")

		// For demonstration, return mock certificate info
		// In practice, you would parse the actual certificate structure
		return {
			subject: "CN=example.com",
			issuer: "CN=Example CA",
			serialNumber: "123456789",
			validFrom: new Date(),
			validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
			fingerprint,
			sha256Fingerprint,
			publicKey: "RSA 2048-bit",
			keySize: 2048,
			signatureAlgorithm: "SHA256withRSA",
			extensions: {},
		}
	}

	/**
	 * Validate certificate chain
	 */
	async validateCertificateChain(certificates: Buffer[]): Promise<CertificateValidationResult> {
		if (certificates.length === 0) {
			return {
				valid: false,
				trusted: false,
				expired: false,
				selfSigned: false,
				revoked: false,
				chainValid: false,
				errors: ["No certificates provided"],
				warnings: [],
				certificateInfo: {} as CertificateInfo,
			}
		}

		if (certificates.length > this.config.maxChainLength) {
			return {
				valid: false,
				trusted: false,
				expired: false,
				selfSigned: false,
				revoked: false,
				chainValid: false,
				errors: [`Certificate chain too long: ${certificates.length} > ${this.config.maxChainLength}`],
				warnings: [],
				certificateInfo: {} as CertificateInfo,
			}
		}

		const leafCert = this.parseCertificate(certificates[0])
		const errors: string[] = []
		const warnings: string[] = []

		// Check expiration
		const now = new Date()
		const expired = leafCert.validTo < now
		const expiringSoon = leafCert.validTo.getTime() - now.getTime() < 30 * 24 * 60 * 60 * 1000 // 30 days

		if (expired) {
			errors.push("Certificate has expired")
		} else if (expiringSoon) {
			warnings.push("Certificate expires within 30 days")
		}

		// Check revocation status
		const revoked = this.revokedCertificates.has(leafCert.serialNumber)
		if (revoked) {
			errors.push("Certificate has been revoked")
		}

		// Check if self-signed
		const selfSigned = leafCert.subject === leafCert.issuer
		if (selfSigned) {
			warnings.push("Certificate is self-signed")
		}

		// Validate chain
		const chainValid = await this.validateChain(certificates)
		if (!chainValid) {
			errors.push("Certificate chain validation failed")
		}

		// Check trust
		const trusted = chainValid && !selfSigned && this.isTrustedCA(leafCert.issuer)

		return {
			valid: errors.length === 0,
			trusted,
			expired,
			selfSigned,
			revoked,
			chainValid,
			errors,
			warnings,
			certificateInfo: leafCert,
		}
	}

	/**
	 * Validate certificate chain integrity
	 */
	private async validateChain(certificates: Buffer[]): Promise<boolean> {
		// Simplified chain validation
		// In practice, you would verify each certificate against its issuer
		return certificates.length > 0
	}

	/**
	 * Check if CA is trusted
	 */
	private isTrustedCA(issuer: string): boolean {
		// Check against custom CAs
		// In practice, you would parse and compare CA certificates
		return this.customCAs.length > 0 || issuer.includes("Trusted CA")
	}

	/**
	 * Add certificate pin
	 */
	addCertificatePin(pin: CertificatePin): void {
		const domain = pin.domain.toLowerCase()
		const pins = this.pins.get(domain) || []

		// Remove existing pin with same ID
		const existingIndex = pins.findIndex((p) => p.id === pin.id)
		if (existingIndex !== -1) {
			pins.splice(existingIndex, 1)
		}

		pins.push(pin)
		this.pins.set(domain, pins)
	}

	/**
	 * Remove certificate pin
	 */
	removeCertificatePin(domain: string, pinId: string): boolean {
		const pins = this.pins.get(domain.toLowerCase())
		if (!pins) return false

		const index = pins.findIndex((pin) => pin.id === pinId)
		if (index === -1) return false

		pins.splice(index, 1)
		if (pins.length === 0) {
			this.pins.delete(domain.toLowerCase())
		}
		return true
	}

	/**
	 * Validate certificate against pins
	 */
	validateCertificatePin(
		domain: string,
		certificate: Buffer,
	): {
		valid: boolean
		pinMatched: boolean
		backupMatched: boolean
		reportOnly: boolean
		errors: string[]
	} {
		const pins = this.getPinsForDomain(domain)
		if (pins.length === 0) {
			return {
				valid: true,
				pinMatched: false,
				backupMatched: false,
				reportOnly: false,
				errors: [],
			}
		}

		const certInfo = this.parseCertificate(certificate)
		const now = Date.now()
		const errors: string[] = []

		// Filter active pins
		const activePins = pins.filter((pin) => !pin.expiresAt || pin.expiresAt > now)
		if (activePins.length === 0) {
			errors.push("All certificate pins have expired")
			return {
				valid: false,
				pinMatched: false,
				backupMatched: false,
				reportOnly: false,
				errors,
			}
		}

		// Check primary pins
		const primaryMatch = activePins.some((pin) => pin.sha256Hash === certInfo.sha256Fingerprint)
		if (primaryMatch) {
			return {
				valid: true,
				pinMatched: true,
				backupMatched: false,
				reportOnly: false,
				errors: [],
			}
		}

		// Check backup pins
		const backupMatch = activePins.some((pin) => pin.backupHashes.includes(certInfo.sha256Fingerprint))
		if (backupMatch) {
			return {
				valid: true,
				pinMatched: false,
				backupMatched: true,
				reportOnly: false,
				errors: [],
			}
		}

		// Check if any pins are report-only
		const reportOnly = activePins.every((pin) => pin.reportOnly)

		errors.push(`Certificate pin validation failed for ${domain}`)
		return {
			valid: reportOnly,
			pinMatched: false,
			backupMatched: false,
			reportOnly,
			errors,
		}
	}

	/**
	 * Get pins for domain (including subdomain matching)
	 */
	private getPinsForDomain(domain: string): CertificatePin[] {
		const normalizedDomain = domain.toLowerCase()
		const pins: CertificatePin[] = []

		// Exact domain match
		const exactPins = this.pins.get(normalizedDomain) || []
		pins.push(...exactPins)

		// Subdomain matching
		const domainParts = normalizedDomain.split(".")
		for (let i = 1; i < domainParts.length; i++) {
			const parentDomain = domainParts.slice(i).join(".")
			const parentPins = this.pins.get(parentDomain) || []
			const subdomainPins = parentPins.filter((pin) => pin.subdomains)
			pins.push(...subdomainPins)
		}

		return pins
	}

	/**
	 * Add revoked certificate
	 */
	addRevokedCertificate(serialNumber: string): void {
		this.revokedCertificates.add(serialNumber)
	}

	/**
	 * Remove revoked certificate
	 */
	removeRevokedCertificate(serialNumber: string): boolean {
		return this.revokedCertificates.delete(serialNumber)
	}

	/**
	 * Check OCSP status
	 */
	async checkOCSPStatus(certificate: CertificateInfo): Promise<{
		status: "good" | "revoked" | "unknown"
		reason?: string
		nextUpdate?: Date
	}> {
		// Simplified OCSP check
		// In practice, you would make an OCSP request to the CA
		if (this.revokedCertificates.has(certificate.serialNumber)) {
			return {
				status: "revoked",
				reason: "Certificate has been revoked",
			}
		}

		return {
			status: "good",
			nextUpdate: new Date(Date.now() + 24 * 60 * 60 * 1000),
		}
	}

	/**
	 * Clean up expired cache entries
	 */
	cleanupCache(): number {
		const now = Date.now()
		let cleanedCount = 0

		for (const [key, entry] of this.certificateCache.entries()) {
			if (now - entry.timestamp > this.config.cacheTTL) {
				this.certificateCache.delete(key)
				cleanedCount++
			}
		}

		return cleanedCount
	}

	/**
	 * Clean up expired pins
	 */
	cleanupExpiredPins(): number {
		const now = Date.now()
		let cleanedCount = 0

		for (const [domain, pins] of this.pins.entries()) {
			const validPins = pins.filter((pin) => !pin.expiresAt || pin.expiresAt > now)
			const expiredCount = pins.length - validPins.length

			if (expiredCount > 0) {
				cleanedCount += expiredCount
				if (validPins.length === 0) {
					this.pins.delete(domain)
				} else {
					this.pins.set(domain, validPins)
				}
			}
		}

		return cleanedCount
	}

	/**
	 * Get certificate manager metrics
	 */
	getMetrics(): {
		cachedCertificates: number
		totalPins: number
		pinnedDomains: number
		revokedCertificates: number
		customCAs: number
	} {
		let totalPins = 0
		for (const pins of this.pins.values()) {
			totalPins += pins.length
		}

		return {
			cachedCertificates: this.certificateCache.size,
			totalPins,
			pinnedDomains: this.pins.size,
			revokedCertificates: this.revokedCertificates.size,
			customCAs: this.customCAs.length,
		}
	}

	/**
	 * Export pins for backup
	 */
	exportPins(): CertificatePin[] {
		const allPins: CertificatePin[] = []
		for (const pins of this.pins.values()) {
			allPins.push(...pins)
		}
		return allPins
	}

	/**
	 * Import pins from backup
	 */
	importPins(pins: CertificatePin[]): number {
		let importedCount = 0
		for (const pin of pins) {
			try {
				CertificatePinSchema.parse(pin)
				this.addCertificatePin(pin)
				importedCount++
			} catch (error) {
				console.warn(`Failed to import pin ${pin.id}:`, error)
			}
		}
		return importedCount
	}
}

/**
 * Global certificate manager instance
 */
let globalCertificateManager: CertificateManager | null = null

/**
 * Get or create the global certificate manager
 */
export function getCertificateManager(config?: CertificateStoreConfig): CertificateManager {
	if (!globalCertificateManager) {
		globalCertificateManager = new CertificateManager(config)
	}
	return globalCertificateManager
}
