/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Security utilities for MCP tool parameter validation and security policy management.
 * Provides centralized security configuration and logging capabilities.
 */

import { z } from "zod"
import { SecurityValidationError } from "./inputSanitizer"
import { SecurityLevel, ValidationResult, ValidationContext } from "./validationSchemas"

/**
 * Security policy configuration
 */
export interface SecurityPolicy {
	/** Default security level for validation */
	defaultSecurityLevel: SecurityLevel
	/** Whether to log security violations */
	logSecurityViolations: boolean
	/** Whether to block execution on security violations */
	blockOnViolations: boolean
	/** Maximum number of violations before blocking a server */
	maxViolationsPerServer: number
	/** Time window for violation counting (in milliseconds) */
	violationTimeWindow: number
	/** Whether to enable detailed security logging */
	enableDetailedLogging: boolean
	/** Custom security rules per server */
	serverSpecificRules: Record<string, Partial<SecurityPolicy>>
}

/**
 * Default security policy with conservative settings
 */
export const DEFAULT_SECURITY_POLICY: SecurityPolicy = {
	defaultSecurityLevel: SecurityLevel.MODERATE,
	logSecurityViolations: true,
	blockOnViolations: true,
	maxViolationsPerServer: 5,
	violationTimeWindow: 300000, // 5 minutes
	enableDetailedLogging: false,
	serverSpecificRules: {},
}

/**
 * Security violation record for tracking and analysis
 */
export interface SecurityViolationRecord {
	id: string
	timestamp: number
	serverName: string
	toolName?: string
	field: string
	violation: string
	severity: "low" | "medium" | "high"
	blocked: boolean
	userAgent?: string
	context: ValidationContext
}

/**
 * Security metrics for monitoring and reporting
 */
export interface SecurityMetrics {
	totalValidations: number
	totalViolations: number
	violationsByServer: Record<string, number>
	violationsBySeverity: Record<string, number>
	blockedRequests: number
	lastViolation?: SecurityViolationRecord
}

/**
 * Security manager class for centralized security operations
 */
export class SecurityManager {
	private policy: SecurityPolicy
	private violations: SecurityViolationRecord[] = []
	private metrics: SecurityMetrics = {
		totalValidations: 0,
		totalViolations: 0,
		violationsByServer: {},
		violationsBySeverity: { low: 0, medium: 0, high: 0 },
		blockedRequests: 0,
	}

	constructor(policy: Partial<SecurityPolicy> = {}) {
		this.policy = { ...DEFAULT_SECURITY_POLICY, ...policy }
	}

	/**
	 * Updates the security policy
	 */
	updatePolicy(updates: Partial<SecurityPolicy>): void {
		this.policy = { ...this.policy, ...updates }
	}

	/**
	 * Gets the current security policy
	 */
	getPolicy(): SecurityPolicy {
		return { ...this.policy }
	}

	/**
	 * Gets security level for a specific server
	 */
	getSecurityLevelForServer(serverName: string): SecurityLevel {
		const serverRules = this.policy.serverSpecificRules[serverName]
		return serverRules?.defaultSecurityLevel ?? this.policy.defaultSecurityLevel
	}

	/**
	 * Records a security violation
	 */
	recordViolation(
		serverName: string,
		field: string,
		violation: string,
		severity: "low" | "medium" | "high",
		context: ValidationContext,
		toolName?: string,
	): SecurityViolationRecord {
		const record: SecurityViolationRecord = {
			id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
			timestamp: Date.now(),
			serverName,
			toolName,
			field,
			violation,
			severity,
			blocked: this.shouldBlockViolation(serverName, severity),
			context,
		}

		this.violations.push(record)
		this.updateMetrics(record)

		if (this.policy.logSecurityViolations) {
			this.logViolation(record)
		}

		// Clean up old violations outside the time window
		this.cleanupOldViolations()

		return record
	}

	/**
	 * Checks if a server should be blocked based on violation history
	 */
	shouldBlockServer(serverName: string): boolean {
		if (!this.policy.blockOnViolations) {
			return false
		}

		const recentViolations = this.getRecentViolationsForServer(serverName)
		return recentViolations.length >= this.policy.maxViolationsPerServer
	}

	/**
	 * Checks if a specific violation should block execution
	 */
	private shouldBlockViolation(serverName: string, severity: "low" | "medium" | "high"): boolean {
		if (!this.policy.blockOnViolations) {
			return false
		}

		// Always block high severity violations
		if (severity === "high") {
			return true
		}

		// Check if server has too many recent violations
		return this.shouldBlockServer(serverName)
	}

	/**
	 * Gets recent violations for a specific server
	 */
	private getRecentViolationsForServer(serverName: string): SecurityViolationRecord[] {
		const cutoffTime = Date.now() - this.policy.violationTimeWindow
		return this.violations.filter((v) => v.serverName === serverName && v.timestamp > cutoffTime)
	}

	/**
	 * Updates security metrics
	 */
	private updateMetrics(record: SecurityViolationRecord): void {
		this.metrics.totalViolations++
		this.metrics.violationsByServer[record.serverName] =
			(this.metrics.violationsByServer[record.serverName] || 0) + 1
		this.metrics.violationsBySeverity[record.severity]++

		if (record.blocked) {
			this.metrics.blockedRequests++
		}

		this.metrics.lastViolation = record
	}

	/**
	 * Logs a security violation
	 */
	private logViolation(record: SecurityViolationRecord): void {
		const logLevel = record.severity === "high" ? "error" : record.severity === "medium" ? "warn" : "info"
		const message = `Security violation: ${record.violation} (Server: ${record.serverName}, Field: ${record.field}, Severity: ${record.severity})`

		if (this.policy.enableDetailedLogging) {
			console[logLevel](message, {
				violationId: record.id,
				context: record.context,
				blocked: record.blocked,
			})
		} else {
			console[logLevel](message)
		}
	}

	/**
	 * Cleans up old violations outside the time window
	 */
	private cleanupOldViolations(): void {
		const cutoffTime = Date.now() - this.policy.violationTimeWindow
		this.violations = this.violations.filter((v) => v.timestamp > cutoffTime)
	}

	/**
	 * Gets current security metrics
	 */
	getMetrics(): SecurityMetrics {
		return { ...this.metrics }
	}

	/**
	 * Gets violation history for a specific server
	 */
	getViolationHistory(serverName: string, limit: number = 50): SecurityViolationRecord[] {
		return this.violations
			.filter((v) => v.serverName === serverName)
			.sort((a, b) => b.timestamp - a.timestamp)
			.slice(0, limit)
	}

	/**
	 * Resets security metrics and violation history
	 */
	reset(): void {
		this.violations = []
		this.metrics = {
			totalValidations: 0,
			totalViolations: 0,
			violationsByServer: {},
			violationsBySeverity: { low: 0, medium: 0, high: 0 },
			blockedRequests: 0,
		}
	}

	/**
	 * Increments validation counter
	 */
	recordValidation(): void {
		this.metrics.totalValidations++
	}
}

/**
 * Global security manager instance
 */
let globalSecurityManager: SecurityManager | null = null

/**
 * Gets or creates the global security manager
 */
export function getSecurityManager(policy?: Partial<SecurityPolicy>): SecurityManager {
	if (!globalSecurityManager) {
		globalSecurityManager = new SecurityManager(policy)
	} else if (policy) {
		globalSecurityManager.updatePolicy(policy)
	}
	return globalSecurityManager
}

/**
 * Processes validation results and handles security violations
 */
export function processValidationResult<T>(
	result: ValidationResult<T>,
	serverName: string,
	toolName?: string,
): ValidationResult<T> {
	const securityManager = getSecurityManager()

	// Record the validation attempt
	securityManager.recordValidation()

	// If validation failed, process security violations
	if (!result.success && result.securityViolations) {
		for (const violation of result.securityViolations) {
			const record = securityManager.recordViolation(
				serverName,
				violation.field,
				violation.violation,
				violation.severity,
				result.context,
				toolName,
			)

			// If this violation should block execution, update the result
			if (record.blocked) {
				return {
					...result,
					securityViolations: [
						...result.securityViolations,
						{
							field: "execution",
							violation: "Execution blocked due to security violation",
							severity: "high",
						},
					],
				}
			}
		}

		// Check if server should be blocked based on violation history
		if (securityManager.shouldBlockServer(serverName)) {
			return {
				...result,
				securityViolations: [
					...(result.securityViolations || []),
					{
						field: "server",
						violation: `Server ${serverName} blocked due to excessive security violations`,
						severity: "high",
					},
				],
			}
		}
	}

	return result
}

/**
 * Creates a security-aware error message
 */
export function createSecurityErrorMessage(
	violations: Array<{ field: string; violation: string; severity: string }>,
	serverName: string,
): string {
	const highSeverityViolations = violations.filter((v) => v.severity === "high")

	if (highSeverityViolations.length > 0) {
		return `Security violation detected in ${serverName}: ${highSeverityViolations[0].violation}. Execution blocked for security reasons.`
	}

	const violationSummary = violations.map((v) => `${v.field}: ${v.violation}`).join("; ")

	return `Security violations detected in ${serverName}: ${violationSummary}`
}

/**
 * Validates that a server name is safe for use
 */
export function validateServerName(serverName: string): boolean {
	// Server names should only contain safe characters
	const safePattern = /^[a-zA-Z0-9._-]+$/
	return safePattern.test(serverName) && serverName.length <= 100
}

/**
 * Validates that a tool name is safe for use
 */
export function validateToolName(toolName: string): boolean {
	// Tool names should only contain safe characters
	const safePattern = /^[a-zA-Z0-9._-]+$/
	return safePattern.test(toolName) && toolName.length <= 100
}

/**
 * Sanitizes error messages to prevent information leakage
 */
export function sanitizeErrorMessage(error: unknown): string {
	if (error instanceof SecurityValidationError) {
		// Don't expose the actual value in security errors
		return `Security validation failed for field '${error.field}': ${error.violationType}`
	}

	if (error instanceof z.ZodError) {
		// Sanitize Zod error messages
		const sanitizedIssues = error.issues.map((issue) => ({
			path: issue.path.join("."),
			message: issue.message,
		}))
		return `Validation failed: ${sanitizedIssues.map((i) => `${i.path}: ${i.message}`).join("; ")}`
	}

	if (error instanceof Error) {
		// Generic error sanitization
		return error.message.replace(/[<>'"&]/g, "")
	}

	return "Unknown validation error"
}

/**
 * Type guards for security validation
 */
export function isSecurityViolation(error: unknown): error is SecurityValidationError {
	return error instanceof SecurityValidationError
}

export function isValidationError(error: unknown): error is z.ZodError {
	return error instanceof z.ZodError
}
