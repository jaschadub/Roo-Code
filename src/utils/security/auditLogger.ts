/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Permission usage tracking and audit trail system.
 * Provides comprehensive logging for security monitoring and compliance.
 */

import * as fs from "fs/promises"
import * as path from "path"
import { z } from "zod"

/**
 * Audit event types
 */
export enum AuditEventType {
	PERMISSION_GRANTED = "permission_granted",
	PERMISSION_DENIED = "permission_denied",
	PERMISSION_USED = "permission_used",
	PERMISSION_EXPIRED = "permission_expired",
	PERMISSION_REVOKED = "permission_revoked",
	PERMISSION_RENEWED = "permission_renewed",
	PERMISSION_DELEGATED = "permission_delegated",
	TOOL_EXECUTION = "tool_execution",
	RESOURCE_ACCESS = "resource_access",
	SECURITY_VIOLATION = "security_violation",
	AUTHENTICATION_ATTEMPT = "authentication_attempt",
	ROLE_ELEVATION = "role_elevation",
	SESSION_CREATED = "session_created",
	SESSION_EXPIRED = "session_expired",
	POLICY_CHANGED = "policy_changed",
	SYSTEM_ERROR = "system_error",
}

/**
 * Audit event severity levels
 */
export enum AuditSeverity {
	LOW = "low",
	MEDIUM = "medium",
	HIGH = "high",
	CRITICAL = "critical",
}

/**
 * Audit event entry
 */
export interface AuditEvent {
	id: string
	timestamp: number
	type: AuditEventType
	severity: AuditSeverity
	serverName?: string
	toolName?: string
	resourceUri?: string
	userId?: string
	sessionId?: string
	ipAddress?: string
	userAgent?: string
	permissionId?: string
	requestId?: string
	success: boolean
	message: string
	details?: Record<string, unknown>
	context?: {
		workspaceId?: string
		projectPath?: string
		environment?: string
		version?: string
	}
	riskScore?: number
	tags?: string[]
}

/**
 * Audit query filters
 */
export interface AuditQueryFilter {
	startTime?: number
	endTime?: number
	types?: AuditEventType[]
	severities?: AuditSeverity[]
	serverNames?: string[]
	toolNames?: string[]
	userIds?: string[]
	sessionIds?: string[]
	success?: boolean
	minRiskScore?: number
	maxRiskScore?: number
	tags?: string[]
	limit?: number
	offset?: number
}

/**
 * Audit statistics
 */
export interface AuditStatistics {
	totalEvents: number
	eventsByType: Record<AuditEventType, number>
	eventsBySeverity: Record<AuditSeverity, number>
	successRate: number
	averageRiskScore: number
	topServers: Array<{ serverName: string; count: number }>
	topTools: Array<{ toolName: string; count: number }>
	recentViolations: AuditEvent[]
	timeRange: { start: number; end: number }
}

/**
 * Audit logger configuration
 */
export interface AuditLoggerConfig {
	logDir: string
	maxLogSize: number // bytes
	maxLogFiles: number
	rotationInterval: number // milliseconds
	enableConsoleOutput: boolean
	enableFileOutput: boolean
	enableMetrics: boolean
	compressionEnabled: boolean
	retentionDays: number
	alertThresholds: {
		violationsPerHour: number
		failureRate: number
		riskScore: number
	}
}

/**
 * Zod schemas
 */
export const AuditEventTypeSchema = z.nativeEnum(AuditEventType)
export const AuditSeveritySchema = z.nativeEnum(AuditSeverity)

export const AuditEventSchema = z.object({
	id: z.string(),
	timestamp: z.number(),
	type: AuditEventTypeSchema,
	severity: AuditSeveritySchema,
	serverName: z.string().optional(),
	toolName: z.string().optional(),
	resourceUri: z.string().optional(),
	userId: z.string().optional(),
	sessionId: z.string().optional(),
	ipAddress: z.string().optional(),
	userAgent: z.string().optional(),
	permissionId: z.string().optional(),
	requestId: z.string().optional(),
	success: z.boolean(),
	message: z.string(),
	details: z.record(z.unknown()).optional(),
	context: z
		.object({
			workspaceId: z.string().optional(),
			projectPath: z.string().optional(),
			environment: z.string().optional(),
			version: z.string().optional(),
		})
		.optional(),
	riskScore: z.number().min(0).max(1).optional(),
	tags: z.array(z.string()).optional(),
})

export const AuditLoggerConfigSchema = z.object({
	logDir: z.string(),
	maxLogSize: z.number().positive(),
	maxLogFiles: z.number().positive(),
	rotationInterval: z.number().positive(),
	enableConsoleOutput: z.boolean(),
	enableFileOutput: z.boolean(),
	enableMetrics: z.boolean(),
	compressionEnabled: z.boolean(),
	retentionDays: z.number().positive(),
	alertThresholds: z.object({
		violationsPerHour: z.number().positive(),
		failureRate: z.number().min(0).max(1),
		riskScore: z.number().min(0).max(1),
	}),
})

/**
 * Default audit logger configuration
 */
export const DEFAULT_AUDIT_CONFIG: AuditLoggerConfig = {
	logDir: ".roo/audit",
	maxLogSize: 10 * 1024 * 1024, // 10MB
	maxLogFiles: 50,
	rotationInterval: 24 * 60 * 60 * 1000, // 24 hours
	enableConsoleOutput: true,
	enableFileOutput: true,
	enableMetrics: true,
	compressionEnabled: false,
	retentionDays: 90,
	alertThresholds: {
		violationsPerHour: 10,
		failureRate: 0.1, // 10%
		riskScore: 0.8,
	},
}

/**
 * Audit logger implementation
 */
export class AuditLogger {
	private config: AuditLoggerConfig
	private currentLogFile: string
	private rotationTimer?: NodeJS.Timeout
	private eventBuffer: AuditEvent[] = []
	private bufferFlushTimer?: NodeJS.Timeout
	private metrics: Map<string, number> = new Map()

	constructor(config: AuditLoggerConfig = DEFAULT_AUDIT_CONFIG) {
		this.config = config
		this.currentLogFile = this.generateLogFileName()
		this.startRotationTimer()
		this.startBufferFlushTimer()
	}

	/**
	 * Initialize audit logger
	 */
	async initialize(): Promise<void> {
		if (this.config.enableFileOutput) {
			await fs.mkdir(this.config.logDir, { recursive: true })
		}
	}

	/**
	 * Generate unique event ID
	 */
	private generateEventId(): string {
		return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
	}

	/**
	 * Generate log file name with timestamp
	 */
	private generateLogFileName(): string {
		const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
		return path.join(this.config.logDir, `audit-${timestamp}.log`)
	}

	/**
	 * Calculate risk score for an event
	 */
	private calculateRiskScore(event: Partial<AuditEvent>): number {
		let riskScore = 0

		// Base risk by event type
		switch (event.type) {
			case AuditEventType.SECURITY_VIOLATION:
				riskScore += 0.8
				break
			case AuditEventType.PERMISSION_DENIED:
				riskScore += 0.6
				break
			case AuditEventType.AUTHENTICATION_ATTEMPT:
				riskScore += event.success ? 0.1 : 0.7
				break
			case AuditEventType.ROLE_ELEVATION:
				riskScore += 0.5
				break
			case AuditEventType.PERMISSION_DELEGATED:
				riskScore += 0.4
				break
			case AuditEventType.TOOL_EXECUTION:
				riskScore += 0.2
				break
			default:
				riskScore += 0.1
		}

		// Increase risk for failures
		if (!event.success) {
			riskScore += 0.3
		}

		// Severity modifier
		switch (event.severity) {
			case AuditSeverity.CRITICAL:
				riskScore += 0.4
				break
			case AuditSeverity.HIGH:
				riskScore += 0.3
				break
			case AuditSeverity.MEDIUM:
				riskScore += 0.2
				break
			case AuditSeverity.LOW:
				riskScore += 0.1
				break
		}

		return Math.min(riskScore, 1.0)
	}

	/**
	 * Log an audit event
	 */
	async logEvent(eventData: Omit<AuditEvent, "id" | "timestamp" | "riskScore">): Promise<void> {
		const event: AuditEvent = {
			id: this.generateEventId(),
			timestamp: Date.now(),
			riskScore: this.calculateRiskScore(eventData),
			...eventData,
		}

		// Validate event
		try {
			AuditEventSchema.parse(event)
		} catch (error) {
			console.error("Invalid audit event:", error)
			return
		}

		// Add to buffer
		this.eventBuffer.push(event)

		// Console output
		if (this.config.enableConsoleOutput) {
			this.logToConsole(event)
		}

		// Update metrics
		if (this.config.enableMetrics) {
			this.updateMetrics(event)
		}

		// Check for immediate alerts
		await this.checkAlerts(event)

		// Flush buffer if it's getting large
		if (this.eventBuffer.length >= 100) {
			await this.flushBuffer()
		}
	}

	/**
	 * Log to console with formatting
	 */
	private logToConsole(event: AuditEvent): void {
		const timestamp = new Date(event.timestamp).toISOString()
		const prefix = `[${timestamp}] [${event.severity.toUpperCase()}] [${event.type}]`

		let message = `${prefix} ${event.message}`
		if (event.serverName) message += ` (server: ${event.serverName})`
		if (event.toolName) message += ` (tool: ${event.toolName})`
		if (event.riskScore !== undefined) message += ` (risk: ${(event.riskScore * 100).toFixed(1)}%)`

		switch (event.severity) {
			case AuditSeverity.CRITICAL:
			case AuditSeverity.HIGH:
				console.error(message)
				break
			case AuditSeverity.MEDIUM:
				console.warn(message)
				break
			default:
				console.log(message)
		}
	}

	/**
	 * Update internal metrics
	 */
	private updateMetrics(event: AuditEvent): void {
		const hour = Math.floor(event.timestamp / (60 * 60 * 1000))

		// Count events by type
		const typeKey = `type_${event.type}`
		this.metrics.set(typeKey, (this.metrics.get(typeKey) || 0) + 1)

		// Count events by severity
		const severityKey = `severity_${event.severity}`
		this.metrics.set(severityKey, (this.metrics.get(severityKey) || 0) + 1)

		// Count violations per hour
		if (event.type === AuditEventType.SECURITY_VIOLATION) {
			const violationKey = `violations_${hour}`
			this.metrics.set(violationKey, (this.metrics.get(violationKey) || 0) + 1)
		}

		// Track failure rate
		const successKey = event.success ? "success_count" : "failure_count"
		this.metrics.set(successKey, (this.metrics.get(successKey) || 0) + 1)
	}

	/**
	 * Check for alert conditions
	 */
	private async checkAlerts(event: AuditEvent): Promise<void> {
		const alerts: string[] = []

		// High risk score alert
		if (event.riskScore && event.riskScore >= this.config.alertThresholds.riskScore) {
			alerts.push(`High risk event detected: ${event.message} (risk: ${(event.riskScore * 100).toFixed(1)}%)`)
		}

		// Security violation alert
		if (event.type === AuditEventType.SECURITY_VIOLATION) {
			alerts.push(`Security violation: ${event.message}`)
		}

		// Check violations per hour
		const hour = Math.floor(event.timestamp / (60 * 60 * 1000))
		const violationKey = `violations_${hour}`
		const violationsThisHour = this.metrics.get(violationKey) || 0
		if (violationsThisHour >= this.config.alertThresholds.violationsPerHour) {
			alerts.push(`High violation rate: ${violationsThisHour} violations in the last hour`)
		}

		// Check failure rate
		const successCount = this.metrics.get("success_count") || 0
		const failureCount = this.metrics.get("failure_count") || 0
		const totalCount = successCount + failureCount
		if (totalCount > 10) {
			// Only check after sufficient events
			const failureRate = failureCount / totalCount
			if (failureRate >= this.config.alertThresholds.failureRate) {
				alerts.push(`High failure rate: ${(failureRate * 100).toFixed(1)}%`)
			}
		}

		// Log alerts
		for (const alert of alerts) {
			console.error(`[SECURITY ALERT] ${alert}`)
		}
	}

	/**
	 * Flush event buffer to file
	 */
	private async flushBuffer(): Promise<void> {
		if (!this.config.enableFileOutput || this.eventBuffer.length === 0) {
			return
		}

		try {
			const logEntries = this.eventBuffer.map((event) => JSON.stringify(event)).join("\n") + "\n"
			await fs.appendFile(this.currentLogFile, logEntries, "utf-8")
			this.eventBuffer = []
		} catch (error) {
			console.error("Failed to flush audit buffer:", error)
		}
	}

	/**
	 * Start buffer flush timer
	 */
	private startBufferFlushTimer(): void {
		this.bufferFlushTimer = setInterval(async () => {
			await this.flushBuffer()
		}, 5000) // Flush every 5 seconds
	}

	/**
	 * Start log rotation timer
	 */
	private startRotationTimer(): void {
		this.rotationTimer = setInterval(async () => {
			await this.rotateLog()
		}, this.config.rotationInterval)
	}

	/**
	 * Rotate log file
	 */
	private async rotateLog(): Promise<void> {
		if (!this.config.enableFileOutput) return

		try {
			// Flush current buffer
			await this.flushBuffer()

			// Generate new log file name
			this.currentLogFile = this.generateLogFileName()

			// Clean up old log files
			await this.cleanupOldLogs()
		} catch (error) {
			console.error("Failed to rotate audit log:", error)
		}
	}

	/**
	 * Clean up old log files
	 */
	private async cleanupOldLogs(): Promise<void> {
		try {
			const files = await fs.readdir(this.config.logDir)
			const logFiles = files
				.filter((file) => file.startsWith("audit-") && file.endsWith(".log"))
				.map((file) => ({
					name: file,
					path: path.join(this.config.logDir, file),
				}))

			// Sort by name (timestamp) and keep only recent files
			logFiles.sort((a, b) => b.name.localeCompare(a.name))

			// Remove files beyond max count
			if (logFiles.length > this.config.maxLogFiles) {
				const filesToDelete = logFiles.slice(this.config.maxLogFiles)
				for (const file of filesToDelete) {
					await fs.unlink(file.path)
				}
			}

			// Remove files older than retention period
			const cutoffTime = Date.now() - this.config.retentionDays * 24 * 60 * 60 * 1000
			for (const file of logFiles) {
				try {
					const stats = await fs.stat(file.path)
					if (stats.mtime.getTime() < cutoffTime) {
						await fs.unlink(file.path)
					}
				} catch {
					// File might have been deleted already
				}
			}
		} catch (error) {
			console.error("Failed to cleanup old audit logs:", error)
		}
	}

	/**
	 * Query audit events
	 */
	async queryEvents(filter: AuditQueryFilter = {}): Promise<AuditEvent[]> {
		if (!this.config.enableFileOutput) {
			return []
		}

		try {
			const files = await fs.readdir(this.config.logDir)
			const logFiles = files
				.filter((file) => file.startsWith("audit-") && file.endsWith(".log"))
				.map((file) => path.join(this.config.logDir, file))

			const events: AuditEvent[] = []

			for (const logFile of logFiles) {
				try {
					const content = await fs.readFile(logFile, "utf-8")
					const lines = content
						.trim()
						.split("\n")
						.filter((line) => line.trim())

					for (const line of lines) {
						try {
							const event = JSON.parse(line) as AuditEvent
							if (this.matchesFilter(event, filter)) {
								events.push(event)
							}
						} catch {
							// Skip invalid JSON lines
						}
					}
				} catch {
					// Skip files that can't be read
				}
			}

			// Sort by timestamp (newest first)
			events.sort((a, b) => b.timestamp - a.timestamp)

			// Apply limit and offset
			const start = filter.offset || 0
			const end = filter.limit ? start + filter.limit : undefined
			return events.slice(start, end)
		} catch (error) {
			console.error("Failed to query audit events:", error)
			return []
		}
	}

	/**
	 * Check if event matches filter
	 */
	private matchesFilter(event: AuditEvent, filter: AuditQueryFilter): boolean {
		if (filter.startTime && event.timestamp < filter.startTime) return false
		if (filter.endTime && event.timestamp > filter.endTime) return false
		if (filter.types && !filter.types.includes(event.type)) return false
		if (filter.severities && !filter.severities.includes(event.severity)) return false
		if (filter.serverNames && event.serverName && !filter.serverNames.includes(event.serverName)) return false
		if (filter.toolNames && event.toolName && !filter.toolNames.includes(event.toolName)) return false
		if (filter.userIds && event.userId && !filter.userIds.includes(event.userId)) return false
		if (filter.sessionIds && event.sessionId && !filter.sessionIds.includes(event.sessionId)) return false
		if (filter.success !== undefined && event.success !== filter.success) return false
		if (filter.minRiskScore && (!event.riskScore || event.riskScore < filter.minRiskScore)) return false
		if (filter.maxRiskScore && (!event.riskScore || event.riskScore > filter.maxRiskScore)) return false
		if (filter.tags && event.tags && !filter.tags.some((tag) => event.tags!.includes(tag))) return false

		return true
	}

	/**
	 * Get audit statistics
	 */
	async getStatistics(timeRange?: { start: number; end: number }): Promise<AuditStatistics> {
		const filter: AuditQueryFilter = timeRange ? { startTime: timeRange.start, endTime: timeRange.end } : {}
		const events = await this.queryEvents(filter)

		const eventsByType: Record<AuditEventType, number> = {} as any
		const eventsBySeverity: Record<AuditSeverity, number> = {} as any
		const serverCounts: Record<string, number> = {}
		const toolCounts: Record<string, number> = {}
		let successCount = 0
		let totalRiskScore = 0
		let riskScoreCount = 0

		// Initialize counters
		Object.values(AuditEventType).forEach((type) => (eventsByType[type] = 0))
		Object.values(AuditSeverity).forEach((severity) => (eventsBySeverity[severity] = 0))

		for (const event of events) {
			eventsByType[event.type]++
			eventsBySeverity[event.severity]++

			if (event.success) successCount++

			if (event.riskScore !== undefined) {
				totalRiskScore += event.riskScore
				riskScoreCount++
			}

			if (event.serverName) {
				serverCounts[event.serverName] = (serverCounts[event.serverName] || 0) + 1
			}

			if (event.toolName) {
				toolCounts[event.toolName] = (toolCounts[event.toolName] || 0) + 1
			}
		}

		const topServers = Object.entries(serverCounts)
			.map(([serverName, count]) => ({ serverName, count }))
			.sort((a, b) => b.count - a.count)
			.slice(0, 10)

		const topTools = Object.entries(toolCounts)
			.map(([toolName, count]) => ({ toolName, count }))
			.sort((a, b) => b.count - a.count)
			.slice(0, 10)

		const recentViolations = events.filter((event) => event.type === AuditEventType.SECURITY_VIOLATION).slice(0, 10)

		return {
			totalEvents: events.length,
			eventsByType,
			eventsBySeverity,
			successRate: events.length > 0 ? successCount / events.length : 0,
			averageRiskScore: riskScoreCount > 0 ? totalRiskScore / riskScoreCount : 0,
			topServers,
			topTools,
			recentViolations,
			timeRange: timeRange || { start: 0, end: Date.now() },
		}
	}

	/**
	 * Dispose of the audit logger
	 */
	async dispose(): Promise<void> {
		if (this.rotationTimer) {
			clearInterval(this.rotationTimer)
		}
		if (this.bufferFlushTimer) {
			clearInterval(this.bufferFlushTimer)
		}
		await this.flushBuffer()
	}

	/**
	 * Convenience methods for common events
	 */
	async logPermissionGranted(
		serverName: string,
		toolName: string,
		permissionId: string,
		userId?: string,
	): Promise<void> {
		await this.logEvent({
			type: AuditEventType.PERMISSION_GRANTED,
			severity: AuditSeverity.LOW,
			serverName,
			toolName,
			permissionId,
			userId,
			success: true,
			message: `Permission granted for tool ${toolName} on server ${serverName}`,
		})
	}

	async logPermissionDenied(serverName: string, toolName: string, reason: string, userId?: string): Promise<void> {
		await this.logEvent({
			type: AuditEventType.PERMISSION_DENIED,
			severity: AuditSeverity.MEDIUM,
			serverName,
			toolName,
			userId,
			success: false,
			message: `Permission denied for tool ${toolName} on server ${serverName}: ${reason}`,
		})
	}

	async logToolExecution(
		serverName: string,
		toolName: string,
		success: boolean,
		userId?: string,
		details?: Record<string, unknown>,
	): Promise<void> {
		await this.logEvent({
			type: AuditEventType.TOOL_EXECUTION,
			severity: success ? AuditSeverity.LOW : AuditSeverity.MEDIUM,
			serverName,
			toolName,
			userId,
			success,
			message: `Tool ${toolName} execution ${success ? "succeeded" : "failed"} on server ${serverName}`,
			details,
		})
	}

	async logSecurityViolation(
		message: string,
		details?: Record<string, unknown>,
		serverName?: string,
		userId?: string,
	): Promise<void> {
		await this.logEvent({
			type: AuditEventType.SECURITY_VIOLATION,
			severity: AuditSeverity.HIGH,
			serverName,
			userId,
			success: false,
			message: `Security violation: ${message}`,
			details,
		})
	}
}
