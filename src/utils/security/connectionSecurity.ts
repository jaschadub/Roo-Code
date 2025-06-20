/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Secure connection establishment and management for MCP network communications.
 * Provides connection security, policy enforcement, and monitoring capabilities.
 */

import * as https from "https"
import * as http from "http"
import { URL } from "url"
import { z } from "zod"
import { NetworkSecurityManager, NetworkSecurityPolicy } from "./networkSecurity"
import { AuthenticationManager, AuthenticationMethod } from "./authenticationManager"
import { CertificateManager } from "./certificateManager"

/**
 * Connection security policy
 */
export interface ConnectionSecurityPolicy {
	/** Enforce secure connections only */
	requireSecureConnections: boolean
	/** Allowed domains for connections */
	allowedDomains: string[]
	/** Blocked domains */
	blockedDomains: string[]
	/** Enable domain validation */
	validateDomains: boolean
	/** Connection timeout in milliseconds */
	connectionTimeout: number
	/** Request timeout in milliseconds */
	requestTimeout: number
	/** Maximum concurrent connections */
	maxConcurrentConnections: number
	/** Enable connection pooling */
	enableConnectionPooling: boolean
	/** Maximum connections per host */
	maxConnectionsPerHost: number
	/** Enable request/response size limits */
	enableSizeLimits: boolean
	/** Maximum request size in bytes */
	maxRequestSize: number
	/** Maximum response size in bytes */
	maxResponseSize: number
	/** Enable rate limiting */
	enableRateLimit: boolean
	/** Rate limit per minute */
	rateLimitPerMinute: number
	/** Enable CORS validation */
	enableCORSValidation: boolean
	/** Allowed CORS origins */
	allowedCORSOrigins: string[]
}

/**
 * Connection monitoring metrics
 */
export interface ConnectionMetrics {
	totalConnections: number
	activeConnections: number
	failedConnections: number
	blockedConnections: number
	averageResponseTime: number
	totalBytesTransferred: number
	securityViolations: number
	rateLimitViolations: number
}

/**
 * Connection security event
 */
export interface ConnectionSecurityEvent {
	id: string
	timestamp: number
	type:
		| "connection_established"
		| "connection_failed"
		| "security_violation"
		| "rate_limit_exceeded"
		| "domain_blocked"
	url: string
	method: string
	statusCode?: number
	responseTime?: number
	bytesTransferred?: number
	securityLevel: "low" | "medium" | "high"
	details: string
	metadata: Record<string, any>
}

/**
 * Secure request options
 */
export interface SecureRequestOptions {
	url: string
	method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
	headers?: Record<string, string>
	body?: string | Buffer
	timeout?: number
	authentication?: {
		method: AuthenticationMethod
		credentials: Record<string, string>
	}
	validateResponse?: boolean
	followRedirects?: boolean
	maxRedirects?: number
}

/**
 * Zod schemas
 */
export const ConnectionSecurityPolicySchema = z.object({
	requireSecureConnections: z.boolean().default(true),
	allowedDomains: z.array(z.string()).default([]),
	blockedDomains: z.array(z.string()).default([]),
	validateDomains: z.boolean().default(true),
	connectionTimeout: z.number().min(1000).max(60000).default(10000),
	requestTimeout: z.number().min(1000).max(300000).default(30000),
	maxConcurrentConnections: z.number().min(1).max(100).default(10),
	enableConnectionPooling: z.boolean().default(true),
	maxConnectionsPerHost: z.number().min(1).max(20).default(5),
	enableSizeLimits: z.boolean().default(true),
	maxRequestSize: z
		.number()
		.min(1024)
		.max(100 * 1024 * 1024)
		.default(10 * 1024 * 1024), // 10MB
	maxResponseSize: z
		.number()
		.min(1024)
		.max(100 * 1024 * 1024)
		.default(50 * 1024 * 1024), // 50MB
	enableRateLimit: z.boolean().default(true),
	rateLimitPerMinute: z.number().min(1).max(1000).default(60),
	enableCORSValidation: z.boolean().default(true),
	allowedCORSOrigins: z.array(z.string()).default(["*"]),
})

export const SecureRequestOptionsSchema = z.object({
	url: z.string().url(),
	method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
	headers: z.record(z.string()).optional(),
	body: z.union([z.string(), z.instanceof(Buffer)]).optional(),
	timeout: z.number().positive().optional(),
	authentication: z
		.object({
			method: z.nativeEnum(AuthenticationMethod),
			credentials: z.record(z.string()),
		})
		.optional(),
	validateResponse: z.boolean().default(true),
	followRedirects: z.boolean().default(true),
	maxRedirects: z.number().min(0).max(10).default(3),
})

/**
 * Default connection security policy
 */
export const DEFAULT_CONNECTION_SECURITY_POLICY: ConnectionSecurityPolicy = {
	requireSecureConnections: true,
	allowedDomains: [],
	blockedDomains: [],
	validateDomains: true,
	connectionTimeout: 10000,
	requestTimeout: 30000,
	maxConcurrentConnections: 10,
	enableConnectionPooling: true,
	maxConnectionsPerHost: 5,
	enableSizeLimits: true,
	maxRequestSize: 10 * 1024 * 1024, // 10MB
	maxResponseSize: 50 * 1024 * 1024, // 50MB
	enableRateLimit: true,
	rateLimitPerMinute: 60,
	enableCORSValidation: true,
	allowedCORSOrigins: ["*"],
}

/**
 * Connection security manager
 */
export class ConnectionSecurityManager {
	private policy: ConnectionSecurityPolicy
	private networkSecurity: NetworkSecurityManager
	private authManager: AuthenticationManager
	private certManager: CertificateManager
	private activeConnections: Map<string, { startTime: number; url: string }> = new Map()
	private connectionPool: Map<string, https.Agent> = new Map()
	private rateLimitCounters: Map<string, { count: number; resetTime: number }> = new Map()
	private securityEvents: ConnectionSecurityEvent[] = []
	private metrics: ConnectionMetrics = {
		totalConnections: 0,
		activeConnections: 0,
		failedConnections: 0,
		blockedConnections: 0,
		averageResponseTime: 0,
		totalBytesTransferred: 0,
		securityViolations: 0,
		rateLimitViolations: 0,
	}

	constructor(
		policy: ConnectionSecurityPolicy = DEFAULT_CONNECTION_SECURITY_POLICY,
		networkSecurity: NetworkSecurityManager,
		authManager: AuthenticationManager,
		certManager: CertificateManager,
	) {
		this.policy = policy
		this.networkSecurity = networkSecurity
		this.authManager = authManager
		this.certManager = certManager
	}

	/**
	 * Update connection security policy
	 */
	updatePolicy(updates: Partial<ConnectionSecurityPolicy>): void {
		this.policy = { ...this.policy, ...updates }
	}

	/**
	 * Validate connection request
	 */
	validateConnectionRequest(url: string): {
		allowed: boolean
		violations: string[]
		securityLevel: "low" | "medium" | "high"
		recommendations: string[]
	} {
		const violations: string[] = []
		const recommendations: string[] = []

		try {
			const parsedURL = new URL(url)

			// Check protocol security
			if (this.policy.requireSecureConnections && parsedURL.protocol !== "https:") {
				violations.push("Insecure protocol not allowed")
				recommendations.push("Use HTTPS instead of HTTP")
			}

			// Check domain validation
			if (this.policy.validateDomains) {
				const hostname = parsedURL.hostname

				// Check blocked domains
				if (this.policy.blockedDomains.some((domain) => this.matchesDomain(hostname, domain))) {
					violations.push(`Domain ${hostname} is blocked`)
				}

				// Check allowed domains (if specified)
				if (this.policy.allowedDomains.length > 0) {
					if (!this.policy.allowedDomains.some((domain) => this.matchesDomain(hostname, domain))) {
						violations.push(`Domain ${hostname} is not in allowed list`)
						recommendations.push("Add domain to allowed list or use an approved domain")
					}
				}
			}

			// Check concurrent connections
			if (this.metrics.activeConnections >= this.policy.maxConcurrentConnections) {
				violations.push("Maximum concurrent connections exceeded")
				recommendations.push("Wait for existing connections to complete")
			}

			// Check rate limits
			if (this.policy.enableRateLimit) {
				const rateLimitResult = this.checkRateLimit(parsedURL.hostname)
				if (!rateLimitResult.allowed) {
					violations.push("Rate limit exceeded")
					recommendations.push("Reduce request frequency")
				}
			}

			// Determine security level
			let securityLevel: "low" | "medium" | "high" = "high"
			if (violations.length > 0) {
				securityLevel = "low"
			} else if (parsedURL.protocol === "http:") {
				securityLevel = "medium"
			}

			return {
				allowed: violations.length === 0,
				violations,
				securityLevel,
				recommendations,
			}
		} catch (error) {
			violations.push("Invalid URL format")
			return {
				allowed: false,
				violations,
				securityLevel: "low",
				recommendations: ["Provide a valid URL"],
			}
		}
	}

	/**
	 * Create secure connection
	 */
	async createSecureConnection(options: SecureRequestOptions): Promise<{
		success: boolean
		response?: any
		error?: string
		securityEvent: ConnectionSecurityEvent
	}> {
		const startTime = Date.now()
		const connectionId = crypto.randomUUID()

		// Validate request
		const validation = this.validateConnectionRequest(options.url)
		if (!validation.allowed) {
			const event = this.createSecurityEvent(
				"security_violation",
				options.url,
				options.method,
				undefined,
				0,
				0,
				validation.securityLevel,
				`Connection blocked: ${validation.violations.join(", ")}`,
				{ violations: validation.violations },
			)
			this.recordSecurityEvent(event)
			this.metrics.blockedConnections++
			this.metrics.securityViolations++

			return {
				success: false,
				error: validation.violations.join("; "),
				securityEvent: event,
			}
		}

		// Validate network security
		const networkValidation = this.networkSecurity.validateURL(options.url)
		if (!networkValidation.allowed) {
			const event = this.createSecurityEvent(
				"security_violation",
				options.url,
				options.method,
				undefined,
				0,
				0,
				"high",
				`Network security violation: ${networkValidation.violations.join(", ")}`,
				{ networkViolations: networkValidation.violations },
			)
			this.recordSecurityEvent(event)
			this.metrics.securityViolations++

			return {
				success: false,
				error: `Network security violation: ${networkValidation.violations.join("; ")}`,
				securityEvent: event,
			}
		}

		try {
			// Track active connection
			this.activeConnections.set(connectionId, { startTime, url: options.url })
			this.metrics.activeConnections++
			this.metrics.totalConnections++

			// Create secure agent
			const parsedURL = new URL(options.url)
			const agent = this.getOrCreateAgent(parsedURL.hostname)

			// Prepare request headers
			const headers = { ...options.headers }

			// Add authentication headers
			if (options.authentication) {
				this.addAuthenticationHeaders(headers, options.authentication)
			}

			// Make request
			const response = await this.makeSecureRequest(options, agent, headers)
			const responseTime = Date.now() - startTime

			// Update metrics
			this.updateMetrics(responseTime, response.bytesTransferred || 0)

			const event = this.createSecurityEvent(
				"connection_established",
				options.url,
				options.method,
				response.statusCode,
				responseTime,
				response.bytesTransferred || 0,
				"high",
				"Secure connection established successfully",
				{ agent: agent.constructor.name },
			)
			this.recordSecurityEvent(event)

			return {
				success: true,
				response,
				securityEvent: event,
			}
		} catch (error) {
			const responseTime = Date.now() - startTime
			this.metrics.failedConnections++

			const event = this.createSecurityEvent(
				"connection_failed",
				options.url,
				options.method,
				undefined,
				responseTime,
				0,
				"medium",
				`Connection failed: ${error instanceof Error ? error.message : String(error)}`,
				{ error: error instanceof Error ? error.message : String(error) },
			)
			this.recordSecurityEvent(event)

			return {
				success: false,
				error: error instanceof Error ? error.message : String(error),
				securityEvent: event,
			}
		} finally {
			// Clean up active connection
			this.activeConnections.delete(connectionId)
			this.metrics.activeConnections--
		}
	}

	/**
	 * Make secure HTTP request
	 */
	private async makeSecureRequest(
		options: SecureRequestOptions,
		agent: https.Agent,
		headers: Record<string, string>,
	): Promise<any> {
		return new Promise((resolve, reject) => {
			const parsedURL = new URL(options.url)
			const isHTTPS = parsedURL.protocol === "https:"

			const requestOptions = {
				hostname: parsedURL.hostname,
				port: parsedURL.port || (isHTTPS ? 443 : 80),
				path: parsedURL.pathname + parsedURL.search,
				method: options.method,
				headers,
				agent: isHTTPS ? agent : undefined,
				timeout: options.timeout || this.policy.requestTimeout,
			}

			const client = isHTTPS ? https : http
			const req = client.request(requestOptions, (res) => {
				let data = Buffer.alloc(0)
				let bytesReceived = 0

				res.on("data", (chunk: Buffer) => {
					bytesReceived += chunk.length

					// Check response size limit
					if (this.policy.enableSizeLimits && bytesReceived > this.policy.maxResponseSize) {
						req.destroy()
						reject(
							new Error(`Response size exceeds limit: ${bytesReceived} > ${this.policy.maxResponseSize}`),
						)
						return
					}

					data = Buffer.concat([data, chunk])
				})

				res.on("end", () => {
					resolve({
						statusCode: res.statusCode,
						headers: res.headers,
						data: data.toString(),
						bytesTransferred: bytesReceived,
					})
				})
			})

			req.on("error", reject)
			req.on("timeout", () => {
				req.destroy()
				reject(new Error("Request timeout"))
			})

			// Send request body if provided
			if (options.body) {
				const bodyBuffer = Buffer.isBuffer(options.body) ? options.body : Buffer.from(options.body)

				// Check request size limit
				if (this.policy.enableSizeLimits && bodyBuffer.length > this.policy.maxRequestSize) {
					reject(
						new Error(`Request size exceeds limit: ${bodyBuffer.length} > ${this.policy.maxRequestSize}`),
					)
					return
				}

				req.write(bodyBuffer)
			}

			req.end()
		})
	}

	/**
	 * Get or create connection agent
	 */
	private getOrCreateAgent(hostname: string): https.Agent {
		if (!this.policy.enableConnectionPooling) {
			return this.networkSecurity.createSecureAgent(hostname)
		}

		let agent = this.connectionPool.get(hostname)
		if (!agent) {
			agent = this.networkSecurity.createSecureAgent(hostname)
			this.connectionPool.set(hostname, agent)
		}
		return agent
	}

	/**
	 * Add authentication headers
	 */
	private addAuthenticationHeaders(
		headers: Record<string, string>,
		auth: { method: AuthenticationMethod; credentials: Record<string, string> },
	): void {
		switch (auth.method) {
			case AuthenticationMethod.API_KEY:
				if (auth.credentials.headerName && auth.credentials.apiKey) {
					headers[auth.credentials.headerName] = auth.credentials.apiKey
				}
				break
			case AuthenticationMethod.BEARER_TOKEN:
				if (auth.credentials.token) {
					headers["Authorization"] = `Bearer ${auth.credentials.token}`
				}
				break
			case AuthenticationMethod.BASIC_AUTH:
				if (auth.credentials.username && auth.credentials.password) {
					const credentials = Buffer.from(
						`${auth.credentials.username}:${auth.credentials.password}`,
					).toString("base64")
					headers["Authorization"] = `Basic ${credentials}`
				}
				break
			case AuthenticationMethod.CUSTOM_HEADER:
				if (auth.credentials.headerName && auth.credentials.value) {
					headers[auth.credentials.headerName] = auth.credentials.value
				}
				break
		}
	}

	/**
	 * Check rate limits
	 */
	private checkRateLimit(hostname: string): { allowed: boolean; remaining: number; resetTime: number } {
		const now = Date.now()
		const windowStart = Math.floor(now / 60000) * 60000 // Start of current minute
		const key = `${hostname}:${windowStart}`

		const counter = this.rateLimitCounters.get(key) || { count: 0, resetTime: windowStart + 60000 }

		if (counter.count >= this.policy.rateLimitPerMinute) {
			this.metrics.rateLimitViolations++
			return {
				allowed: false,
				remaining: 0,
				resetTime: counter.resetTime,
			}
		}

		counter.count++
		this.rateLimitCounters.set(key, counter)

		return {
			allowed: true,
			remaining: this.policy.rateLimitPerMinute - counter.count,
			resetTime: counter.resetTime,
		}
	}

	/**
	 * Match domain against pattern (supports wildcards)
	 */
	private matchesDomain(hostname: string, pattern: string): boolean {
		if (pattern === "*") return true
		if (pattern.startsWith("*.")) {
			const domain = pattern.slice(2)
			return hostname === domain || hostname.endsWith("." + domain)
		}
		return hostname === pattern
	}

	/**
	 * Create security event
	 */
	private createSecurityEvent(
		type: ConnectionSecurityEvent["type"],
		url: string,
		method: string,
		statusCode?: number,
		responseTime?: number,
		bytesTransferred?: number,
		securityLevel: "low" | "medium" | "high" = "medium",
		details: string = "",
		metadata: Record<string, any> = {},
	): ConnectionSecurityEvent {
		return {
			id: crypto.randomUUID(),
			timestamp: Date.now(),
			type,
			url,
			method,
			statusCode,
			responseTime,
			bytesTransferred,
			securityLevel,
			details,
			metadata,
		}
	}

	/**
	 * Record security event
	 */
	private recordSecurityEvent(event: ConnectionSecurityEvent): void {
		this.securityEvents.push(event)

		// Keep only last 1000 events
		if (this.securityEvents.length > 1000) {
			this.securityEvents = this.securityEvents.slice(-1000)
		}

		// Log high-severity events
		if (event.securityLevel === "high" && event.type === "security_violation") {
			console.warn(`[ConnectionSecurity] ${event.details}`, event.metadata)
		}
	}

	/**
	 * Update metrics
	 */
	private updateMetrics(responseTime: number, bytesTransferred: number): void {
		this.metrics.averageResponseTime =
			(this.metrics.averageResponseTime * (this.metrics.totalConnections - 1) + responseTime) /
			this.metrics.totalConnections
		this.metrics.totalBytesTransferred += bytesTransferred
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
	 * Get connection metrics
	 */
	getMetrics(): ConnectionMetrics {
		return { ...this.metrics }
	}

	/**
	 * Get security events
	 */
	getSecurityEvents(limit: number = 100): ConnectionSecurityEvent[] {
		return this.securityEvents.slice(-limit)
	}

	/**
	 * Clear security events
	 */
	clearSecurityEvents(): void {
		this.securityEvents = []
	}
}

/**
 * Global connection security manager instance
 */
let globalConnectionSecurityManager: ConnectionSecurityManager | null = null

/**
 * Get or create the global connection security manager
 */
export function getConnectionSecurityManager(
	policy?: ConnectionSecurityPolicy,
	networkSecurity?: NetworkSecurityManager,
	authManager?: AuthenticationManager,
	certManager?: CertificateManager,
): ConnectionSecurityManager {
	if (!globalConnectionSecurityManager) {
		if (!networkSecurity || !authManager || !certManager) {
			throw new Error(
				"NetworkSecurityManager, AuthenticationManager, and CertificateManager are required for first initialization",
			)
		}
		globalConnectionSecurityManager = new ConnectionSecurityManager(
			policy,
			networkSecurity,
			authManager,
			certManager,
		)
	} else if (policy) {
		globalConnectionSecurityManager.updatePolicy(policy)
	}
	return globalConnectionSecurityManager
}
