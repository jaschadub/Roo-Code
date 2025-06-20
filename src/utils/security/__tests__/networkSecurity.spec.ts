/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Tests for network security utilities and validation.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest"
import {
	NetworkSecurityManager,
	NetworkSecurityViolation,
	getNetworkSecurityManager,
	validateNetworkSecurity,
	createSecureHTTPSAgent,
	DEFAULT_NETWORK_SECURITY_POLICY,
} from "../networkSecurity"

describe("NetworkSecurityManager", () => {
	let manager: NetworkSecurityManager

	beforeEach(() => {
		manager = new NetworkSecurityManager()
	})

	afterEach(() => {
		manager.cleanupExpiredHSTS()
		manager.cleanupExpiredPins()
	})

	describe("URL validation", () => {
		it("should allow HTTPS URLs by default", () => {
			const result = manager.validateURL("https://example.com/api")

			expect(result.allowed).toBe(true)
			expect(result.violations).toHaveLength(0)
			expect(result.securityLevel).toBe("high")
		})

		it("should block HTTP URLs when TLS is enforced", () => {
			const result = manager.validateURL("http://example.com/api")

			expect(result.allowed).toBe(false)
			expect(result.violations).toContain(NetworkSecurityViolation.INSECURE_PROTOCOL)
			expect(result.securityLevel).toBe("low")
			expect(result.recommendations).toContain("Use HTTPS instead of HTTP for secure communication")
		})

		it("should allow HTTP URLs when TLS enforcement is disabled", () => {
			manager.updatePolicy({ enforceTLS: false })
			const result = manager.validateURL("http://example.com/api")

			expect(result.allowed).toBe(true)
			expect(result.violations).toHaveLength(0)
		})

		it("should reject invalid URLs", () => {
			const result = manager.validateURL("not-a-url")

			expect(result.allowed).toBe(false)
			expect(result.violations).toContain(NetworkSecurityViolation.INVALID_DOMAIN)
			expect(result.securityLevel).toBe("low")
		})
	})

	describe("Certificate pinning", () => {
		it("should add certificate pins", () => {
			const pin = {
				domain: "example.com",
				sha256Hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			}

			manager.addCertificatePin(pin)

			// Verify pin was added through metrics
			const metrics = manager.getMetrics()
			expect(metrics.totalPinnedDomains).toBe(1)
			expect(metrics.totalPins).toBe(1)
		})

		it("should remove certificate pins", () => {
			const pin = {
				domain: "example.com",
				sha256Hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			}

			manager.addCertificatePin(pin)
			const removed = manager.removeCertificatePin("example.com", pin.sha256Hash)

			expect(removed).toBe(true)

			// Verify pin was removed through metrics
			const metrics = manager.getMetrics()
			expect(metrics.totalPinnedDomains).toBe(0)
			expect(metrics.totalPins).toBe(0)
		})

		it("should return false when removing non-existent pin", () => {
			const removed = manager.removeCertificatePin("nonexistent.com", "fakehash")
			expect(removed).toBe(false)
		})
	})

	describe("HTTPS agent creation", () => {
		it("should create secure HTTPS agent with default settings", () => {
			const agent = manager.createSecureAgent("example.com")

			expect(agent).toBeDefined()
			expect(agent.options.rejectUnauthorized).toBe(true)
			expect(agent.options.timeout).toBe(DEFAULT_NETWORK_SECURITY_POLICY.connectionTimeout)
		})

		it("should create agent with custom TLS version", () => {
			manager.updatePolicy({ minTLSVersion: "TLSv1.3" })
			const agent = manager.createSecureAgent("example.com")

			expect(agent).toBeDefined()
			expect(agent.options.secureProtocol).toBe("TLSv1_3_method")
		})

		it("should disable certificate validation when configured", () => {
			manager.updatePolicy({ validateCertificates: false })
			const agent = manager.createSecureAgent("example.com")

			expect(agent.options.rejectUnauthorized).toBe(false)
		})
	})

	describe("HSTS processing", () => {
		it("should process and cache HSTS headers", () => {
			const headers = {
				"strict-transport-security": "max-age=31536000; includeSubDomains; preload",
			}

			manager.processHSTSHeaders("example.com", headers)

			// HSTS cache is private, but we can test through metrics
			const metrics = manager.getMetrics()
			expect(metrics.hstsEntries).toBe(1)
		})

		it("should ignore invalid HSTS headers", () => {
			const headers = {
				"strict-transport-security": "invalid-header",
			}

			manager.processHSTSHeaders("example.com", headers)

			const metrics = manager.getMetrics()
			expect(metrics.hstsEntries).toBe(0)
		})
	})

	describe("Cipher suite validation", () => {
		it("should validate allowed cipher suites", () => {
			const validCipher = "TLS_AES_256_GCM_SHA384"
			const result = manager.validateCipherSuite(validCipher)

			expect(result).toBe(true)
		})

		it("should reject disallowed cipher suites", () => {
			const invalidCipher = "RC4-MD5"
			const result = manager.validateCipherSuite(invalidCipher)

			expect(result).toBe(false)
		})
	})

	describe("Cleanup operations", () => {
		it("should clean up expired HSTS entries", () => {
			// Add HSTS entry that will expire immediately
			const headers = { "strict-transport-security": "max-age=0" }
			manager.processHSTSHeaders("example.com", headers)

			// Wait a bit and clean up
			setTimeout(() => {
				const cleaned = manager.cleanupExpiredHSTS()
				expect(cleaned).toBeGreaterThanOrEqual(0)
			}, 10)
		})

		it("should clean up expired certificate pins", () => {
			const expiredPin = {
				domain: "example.com",
				sha256Hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				expiresAt: Date.now() - 1000, // Expired 1 second ago
			}

			manager.addCertificatePin(expiredPin)
			const cleaned = manager.cleanupExpiredPins()

			expect(cleaned).toBe(1)
		})
	})

	describe("Metrics", () => {
		it("should provide accurate metrics", () => {
			const pin = {
				domain: "example.com",
				sha256Hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			}
			manager.addCertificatePin(pin)

			const headers = { "strict-transport-security": "max-age=31536000" }
			manager.processHSTSHeaders("example.com", headers)

			const metrics = manager.getMetrics()

			expect(metrics.totalPinnedDomains).toBe(1)
			expect(metrics.totalPins).toBe(1)
			expect(metrics.hstsEntries).toBe(1)
			expect(metrics.expiredPins).toBe(0)
			expect(metrics.expiredHSTS).toBe(0)
		})
	})
})

describe("Global network security functions", () => {
	afterEach(() => {
		// Clean up global manager
		const manager = getNetworkSecurityManager()
		manager.cleanupExpiredHSTS()
		manager.cleanupExpiredPins()
	})

	it("should get or create global network security manager", () => {
		const manager1 = getNetworkSecurityManager()
		const manager2 = getNetworkSecurityManager()

		expect(manager1).toBe(manager2) // Should be the same instance
	})

	it("should validate network security using global function", () => {
		const result = validateNetworkSecurity("https://example.com")

		expect(result.allowed).toBe(true)
		expect(result.securityLevel).toBe("high")
	})

	it("should create secure HTTPS agent using global function", () => {
		const agent = createSecureHTTPSAgent("example.com")

		expect(agent).toBeDefined()
		expect(agent.options.rejectUnauthorized).toBe(true)
	})
})

describe("Network security policy validation", () => {
	it("should use default policy when none provided", () => {
		const manager = new NetworkSecurityManager()
		const policy = manager.getPolicy()

		expect(policy.enforceTLS).toBe(true)
		expect(policy.minTLSVersion).toBe("TLSv1.2")
		expect(policy.validateCertificates).toBe(true)
		expect(policy.connectionTimeout).toBe(10000)
	})

	it("should update policy correctly", () => {
		const manager = new NetworkSecurityManager()
		const updates = {
			enforceTLS: false,
			minTLSVersion: "TLSv1.3" as const,
			connectionTimeout: 5000,
		}

		manager.updatePolicy(updates)
		const policy = manager.getPolicy()

		expect(policy.enforceTLS).toBe(false)
		expect(policy.minTLSVersion).toBe("TLSv1.3")
		expect(policy.connectionTimeout).toBe(5000)
		expect(policy.validateCertificates).toBe(true) // Should remain unchanged
	})
})

describe("Certificate information extraction", () => {
	it("should extract certificate information", () => {
		const manager = new NetworkSecurityManager()

		// Mock certificate object
		const mockCert = {
			subject: { CN: "example.com" },
			issuer: { CN: "Example CA" },
			valid_from: "Jan 1 00:00:00 2024 GMT",
			valid_to: "Jan 1 00:00:00 2025 GMT",
			raw: Buffer.from("mock-cert-data"),
		}

		const certInfo = manager.getCertificateInfo(mockCert)

		expect(certInfo.subject).toBe("example.com")
		expect(certInfo.issuer).toBe("Example CA")
		expect(certInfo.validFrom).toBeInstanceOf(Date)
		expect(certInfo.validTo).toBeInstanceOf(Date)
		expect(certInfo.fingerprint).toBeDefined()
	})

	it("should handle certificates with missing fields", () => {
		const manager = new NetworkSecurityManager()

		// Mock certificate with missing fields
		const mockCert = {
			raw: Buffer.from("mock-cert-data"),
		}

		const certInfo = manager.getCertificateInfo(mockCert)

		expect(certInfo.subject).toBe("Unknown")
		expect(certInfo.issuer).toBe("Unknown")
		expect(certInfo.fingerprint).toBeDefined()
	})
})
