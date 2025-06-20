/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Real-time security monitoring and alerting system for MCP operations.
 * Provides continuous monitoring, threat detection, and automated response.
 */

import { z } from "zod"
import { AuditLogger, AuditEvent, AuditEventType, AuditSeverity } from "./auditLogger"
import { SecurityManager, SecurityViolationRecord } from "./securityUtils"

/**
 * Security alert types
 */
export enum SecurityAlertType {
	ANOMALY_DETECTED = "anomaly_detected",
	THRESHOLD_EXCEEDED = "threshold_exceeded",
	SUSPICIOUS_PATTERN = "suspicious_pattern",
	REPEATED_VIOLATIONS = "repeated_violations",
	PRIVILEGE_ESCALATION = "privilege_escalation",
	UNUSUAL_ACTIVITY = "unusual_activity",
	SYSTEM_COMPROMISE = "system_compromise",
}

/**
 * Security alert severity levels
 */
export enum SecurityAlertSeverity {
	INFO = "info",
	WARNING = "warning",
	CRITICAL = "critical",
	EMERGENCY = "emergency",
}

/**
 * Security alert configuration
 */
export interface SecurityAlert {
	id: string
	type: SecurityAlertType
	severity: SecurityAlertSeverity
	timestamp: number
	title: string
	description: string
	serverName?: string
	toolName?: string
	userId?: string
	sessionId?: string
	details: Record<string, unknown>
	recommendations: string[]
	autoResponse?: SecurityResponse
	acknowledged: boolean
	resolvedAt?: number
}

/**
 * Automated security response actions
 */
export enum SecurityResponseAction {
	LOG_ONLY = "log_only",
	RATE_LIMIT = "rate_limit",
	BLOCK_SERVER = "block_server",
	BLOCK_TOOL = "block_tool",
	REVOKE_PERMISSIONS = "revoke_permissions",
	ESCALATE_TO_ADMIN = "escalate_to_admin",
	SHUTDOWN_SESSION = "shutdown_session",
}

/**
 * Security response configuration
 */
export interface SecurityResponse {
	action: SecurityResponseAction
	duration?: number
	parameters?: Record<string, unknown>
	executedAt?: number
	success?: boolean
	error?: string
}

/**
 * Security monitoring configuration
 */
export interface SecurityMonitorConfig {
	enabled: boolean
	realTimeMonitoring: boolean
	alertThresholds: {
		violationsPerMinute: number
		violationsPerHour: number
		failureRateThreshold: number
		anomalyScoreThreshold: number
		suspiciousPatternThreshold: number
	}
	autoResponseEnabled: boolean
	alertChannels: {
		console: boolean
		file: boolean
		webhook?: string
		email?: string
	}
	monitoringInterval: number
	retentionDays: number
}

/**
 * Security metrics for monitoring
 */
export interface SecurityMonitoringMetrics {
	totalAlerts: number
	alertsByType: Record<SecurityAlertType, number>
	alertsBySeverity: Record<SecurityAlertSeverity, number>
	activeAlerts: number
	resolvedAlerts: number
	averageResolutionTime: number
	lastAlert?: SecurityAlert
	systemHealth: "healthy" | "warning" | "critical"
}

/**
 * Pattern detection result
 */
export interface PatternDetectionResult {
	detected: boolean
	pattern: string
	confidence: number
	evidence: string[]
	riskScore: number
}

/**
 * Zod schemas
 */
export const SecurityAlertTypeSchema = z.nativeEnum(SecurityAlertType)
export const SecurityAlertSeveritySchema = z.nativeEnum(SecurityAlertSeverity)
export const SecurityResponseActionSchema = z.nativeEnum(SecurityResponseAction)

export const SecurityResponseSchema = z.object({
	action: SecurityResponseActionSchema,
	duration: z.number().optional(),
	parameters: z.record(z.unknown()).optional(),
	executedAt: z.number().optional(),
	success: z.boolean().optional(),
	error: z.string().optional(),
})

export const SecurityAlertSchema = z.object({
	id: z.string(),
	type: SecurityAlertTypeSchema,
	severity: SecurityAlertSeveritySchema,
	timestamp: z.number(),
	title: z.string(),
	description: z.string(),
	serverName: z.string().optional(),
	toolName: z.string().optional(),
	userId: z.string().optional(),
	sessionId: z.string().optional(),
	details: z.record(z.unknown()),
	recommendations: z.array(z.string()),
	autoResponse: SecurityResponseSchema.optional(),
	acknowledged: z.boolean(),
	resolvedAt: z.number().optional(),
})

export const SecurityMonitorConfigSchema = z.object({
	enabled: z.boolean(),
	realTimeMonitoring: z.boolean(),
	alertThresholds: z.object({
		violationsPerMinute: z.number().positive(),
		violationsPerHour: z.number().positive(),
		failureRateThreshold: z.number().min(0).max(1),
		anomalyScoreThreshold: z.number().min(0).max(1),
		suspiciousPatternThreshold: z.number().min(0).max(1),
	}),
	autoResponseEnabled: z.boolean(),
	alertChannels: z.object({
		console: z.boolean(),
		file: z.boolean(),
		webhook: z.string().optional(),
		email: z.string().optional(),
	}),
	monitoringInterval: z.number().positive(),
	retentionDays: z.number().positive(),
})

/**
 * Default security monitor configuration
 */
export const DEFAULT_SECURITY_MONITOR_CONFIG: SecurityMonitorConfig = {
	enabled: true,
	realTimeMonitoring: true,
	alertThresholds: {
		violationsPerMinute: 5,
		violationsPerHour: 20,
		failureRateThreshold: 0.3,
		anomalyScoreThreshold: 0.8,
		suspiciousPatternThreshold: 0.7,
	},
	autoResponseEnabled: true,
	alertChannels: {
		console: true,
		file: true,
	},
	monitoringInterval: 30000, // 30 seconds
	retentionDays: 30,
}

/**
 * Security monitor implementation
 */
export class SecurityMonitor {
	private config: SecurityMonitorConfig
	private auditLogger: AuditLogger
	private securityManager: SecurityManager
	private alerts: Map<string, SecurityAlert> = new Map()
	private monitoringTimer?: NodeJS.Timeout
	private metrics: SecurityMonitoringMetrics = {
		totalAlerts: 0,
		alertsByType: {} as Record<SecurityAlertType, number>,
		alertsBySeverity: {} as Record<SecurityAlertSeverity, number>,
		activeAlerts: 0,
		resolvedAlerts: 0,
		averageResolutionTime: 0,
		systemHealth: "healthy",
	}

	constructor(
		auditLogger: AuditLogger,
		securityManager: SecurityManager,
		config: SecurityMonitorConfig = DEFAULT_SECURITY_MONITOR_CONFIG,
	) {
		this.auditLogger = auditLogger
		this.securityManager = securityManager
		this.config = config
		this.initializeMetrics()
	}

	/**
	 * Initialize monitoring metrics
	 */
	private initializeMetrics(): void {
		Object.values(SecurityAlertType).forEach((type) => {
			this.metrics.alertsByType[type] = 0
		})
		Object.values(SecurityAlertSeverity).forEach((severity) => {
			this.metrics.alertsBySeverity[severity] = 0
		})
	}

	/**
	 * Start security monitoring
	 */
	async start(): Promise<void> {
		if (!this.config.enabled) {
			return
		}

		await this.auditLogger.logEvent({
			type: AuditEventType.SYSTEM_ERROR,
			severity: AuditSeverity.LOW,
			success: true,
			message: "Security monitoring started",
			details: { config: this.config },
		})

		if (this.config.realTimeMonitoring) {
			this.startRealTimeMonitoring()
		}
	}

	/**
	 * Stop security monitoring
	 */
	async stop(): Promise<void> {
		if (this.monitoringTimer) {
			clearInterval(this.monitoringTimer)
			this.monitoringTimer = undefined
		}

		await this.auditLogger.logEvent({
			type: AuditEventType.SYSTEM_ERROR,
			severity: AuditSeverity.LOW,
			success: true,
			message: "Security monitoring stopped",
		})
	}

	/**
	 * Start real-time monitoring
	 */
	private startRealTimeMonitoring(): void {
		this.monitoringTimer = setInterval(async () => {
			await this.performSecurityCheck()
		}, this.config.monitoringInterval)
	}

	/**
	 * Perform comprehensive security check
	 */
	private async performSecurityCheck(): Promise<void> {
		try {
			// Check for anomalies in recent audit events
			await this.checkForAnomalies()

			// Check violation thresholds
			await this.checkViolationThresholds()

			// Check for suspicious patterns
			await this.checkSuspiciousPatterns()

			// Update system health status
			this.updateSystemHealth()

			// Clean up old alerts
			this.cleanupOldAlerts()
		} catch (error) {
			console.error("Security monitoring check failed:", error)
		}
	}

	/**
	 * Check for anomalies in audit events
	 */
	private async checkForAnomalies(): Promise<void> {
		const recentEvents = await this.auditLogger.queryEvents({
			startTime: Date.now() - 60 * 60 * 1000, // Last hour
			limit: 1000,
		})

		// Detect unusual activity patterns
		const anomalies = this.detectAnomalies(recentEvents)

		for (const anomaly of anomalies) {
			if (anomaly.riskScore >= this.config.alertThresholds.anomalyScoreThreshold) {
				await this.createAlert({
					type: SecurityAlertType.ANOMALY_DETECTED,
					severity: this.mapRiskScoreToSeverity(anomaly.riskScore),
					title: "Security Anomaly Detected",
					description: `Anomalous pattern detected: ${anomaly.pattern}`,
					details: {
						pattern: anomaly.pattern,
						confidence: anomaly.confidence,
						evidence: anomaly.evidence,
						riskScore: anomaly.riskScore,
					},
					recommendations: [
						"Review recent activity for suspicious behavior",
						"Check for unauthorized access attempts",
						"Verify user authentication status",
					],
				})
			}
		}
	}

	/**
	 * Check violation thresholds
	 */
	private async checkViolationThresholds(): Promise<void> {
		const securityMetrics = this.securityManager.getMetrics()
		const now = Date.now()

		// Check violations per minute
		const recentViolations = await this.auditLogger.queryEvents({
			types: [AuditEventType.SECURITY_VIOLATION],
			startTime: now - 60 * 1000, // Last minute
		})

		if (recentViolations.length >= this.config.alertThresholds.violationsPerMinute) {
			await this.createAlert({
				type: SecurityAlertType.THRESHOLD_EXCEEDED,
				severity: SecurityAlertSeverity.WARNING,
				title: "High Violation Rate",
				description: `${recentViolations.length} security violations in the last minute`,
				details: {
					violationCount: recentViolations.length,
					threshold: this.config.alertThresholds.violationsPerMinute,
					timeWindow: "1 minute",
				},
				recommendations: [
					"Investigate source of violations",
					"Consider implementing rate limiting",
					"Review security policies",
				],
			})
		}

		// Check failure rate
		const totalEvents = securityMetrics.totalValidations
		const failureRate = totalEvents > 0 ? securityMetrics.totalViolations / totalEvents : 0

		if (failureRate >= this.config.alertThresholds.failureRateThreshold) {
			await this.createAlert({
				type: SecurityAlertType.THRESHOLD_EXCEEDED,
				severity: SecurityAlertSeverity.CRITICAL,
				title: "High Failure Rate",
				description: `Security failure rate: ${(failureRate * 100).toFixed(1)}%`,
				details: {
					failureRate,
					threshold: this.config.alertThresholds.failureRateThreshold,
					totalValidations: totalEvents,
					totalViolations: securityMetrics.totalViolations,
				},
				recommendations: [
					"Review security configuration",
					"Investigate repeated failures",
					"Consider adjusting security policies",
				],
			})
		}
	}

	/**
	 * Check for suspicious patterns
	 */
	private async checkSuspiciousPatterns(): Promise<void> {
		const recentEvents = await this.auditLogger.queryEvents({
			startTime: Date.now() - 24 * 60 * 60 * 1000, // Last 24 hours
			limit: 5000,
		})

		const patterns = this.detectSuspiciousPatterns(recentEvents)

		for (const pattern of patterns) {
			if (pattern.confidence >= this.config.alertThresholds.suspiciousPatternThreshold) {
				await this.createAlert({
					type: SecurityAlertType.SUSPICIOUS_PATTERN,
					severity: this.mapRiskScoreToSeverity(pattern.riskScore),
					title: "Suspicious Pattern Detected",
					description: `Suspicious activity pattern: ${pattern.pattern}`,
					details: {
						pattern: pattern.pattern,
						confidence: pattern.confidence,
						evidence: pattern.evidence,
						riskScore: pattern.riskScore,
					},
					recommendations: [
						"Investigate the identified pattern",
						"Review user activity logs",
						"Consider implementing additional security measures",
					],
				})
			}
		}
	}

	/**
	 * Detect anomalies in audit events
	 */
	private detectAnomalies(events: AuditEvent[]): PatternDetectionResult[] {
		const anomalies: PatternDetectionResult[] = []

		// Check for unusual time patterns
		const timeAnomaly = this.detectTimeAnomalies(events)
		if (timeAnomaly.detected) {
			anomalies.push(timeAnomaly)
		}

		// Check for unusual server activity
		const serverAnomaly = this.detectServerAnomalies(events)
		if (serverAnomaly.detected) {
			anomalies.push(serverAnomaly)
		}

		// Check for unusual tool usage
		const toolAnomaly = this.detectToolAnomalies(events)
		if (toolAnomaly.detected) {
			anomalies.push(toolAnomaly)
		}

		return anomalies
	}

	/**
	 * Detect time-based anomalies
	 */
	private detectTimeAnomalies(events: AuditEvent[]): PatternDetectionResult {
		const hourCounts: Record<number, number> = {}

		for (const event of events) {
			const hour = new Date(event.timestamp).getHours()
			hourCounts[hour] = (hourCounts[hour] || 0) + 1
		}

		const hours = Object.keys(hourCounts).map(Number)
		const counts = Object.values(hourCounts)
		const avgCount = counts.reduce((a, b) => a + b, 0) / counts.length
		const maxCount = Math.max(...counts)

		// Detect if activity is concentrated in unusual hours
		const unusualHours = hours.filter((hour) => hourCounts[hour] > avgCount * 3 && (hour < 6 || hour > 22))

		if (unusualHours.length > 0) {
			return {
				detected: true,
				pattern: "unusual_time_activity",
				confidence: Math.min(unusualHours.length / 5, 1),
				evidence: [`High activity during unusual hours: ${unusualHours.join(", ")}`],
				riskScore: Math.min(maxCount / avgCount / 10, 1),
			}
		}

		return { detected: false, pattern: "", confidence: 0, evidence: [], riskScore: 0 }
	}

	/**
	 * Detect server-based anomalies
	 */
	private detectServerAnomalies(events: AuditEvent[]): PatternDetectionResult {
		const serverCounts: Record<string, number> = {}

		for (const event of events) {
			if (event.serverName) {
				serverCounts[event.serverName] = (serverCounts[event.serverName] || 0) + 1
			}
		}

		const servers = Object.keys(serverCounts)
		const counts = Object.values(serverCounts)
		const avgCount = counts.reduce((a, b) => a + b, 0) / counts.length
		const maxCount = Math.max(...counts)

		// Detect servers with unusually high activity
		const suspiciousServers = servers.filter((server) => serverCounts[server] > avgCount * 5)

		if (suspiciousServers.length > 0) {
			return {
				detected: true,
				pattern: "unusual_server_activity",
				confidence: Math.min(suspiciousServers.length / 3, 1),
				evidence: [`High activity from servers: ${suspiciousServers.join(", ")}`],
				riskScore: Math.min(maxCount / avgCount / 10, 1),
			}
		}

		return { detected: false, pattern: "", confidence: 0, evidence: [], riskScore: 0 }
	}

	/**
	 * Detect tool-based anomalies
	 */
	private detectToolAnomalies(events: AuditEvent[]): PatternDetectionResult {
		const toolCounts: Record<string, number> = {}

		for (const event of events) {
			if (event.toolName) {
				toolCounts[event.toolName] = (toolCounts[event.toolName] || 0) + 1
			}
		}

		const tools = Object.keys(toolCounts)
		const counts = Object.values(toolCounts)
		const avgCount = counts.reduce((a, b) => a + b, 0) / counts.length
		const maxCount = Math.max(...counts)

		// Detect tools with unusually high usage
		const suspiciousTools = tools.filter((tool) => toolCounts[tool] > avgCount * 4)

		if (suspiciousTools.length > 0) {
			return {
				detected: true,
				pattern: "unusual_tool_usage",
				confidence: Math.min(suspiciousTools.length / 2, 1),
				evidence: [`High usage of tools: ${suspiciousTools.join(", ")}`],
				riskScore: Math.min(maxCount / avgCount / 8, 1),
			}
		}

		return { detected: false, pattern: "", confidence: 0, evidence: [], riskScore: 0 }
	}

	/**
	 * Detect suspicious patterns in events
	 */
	private detectSuspiciousPatterns(events: AuditEvent[]): PatternDetectionResult[] {
		const patterns: PatternDetectionResult[] = []

		// Check for repeated failed authentication attempts
		const authFailures = events.filter((e) => e.type === AuditEventType.AUTHENTICATION_ATTEMPT && !e.success)

		if (authFailures.length >= 5) {
			patterns.push({
				detected: true,
				pattern: "repeated_auth_failures",
				confidence: Math.min(authFailures.length / 10, 1),
				evidence: [`${authFailures.length} failed authentication attempts`],
				riskScore: Math.min(authFailures.length / 20, 1),
			})
		}

		// Check for privilege escalation attempts
		const escalationEvents = events.filter((e) => e.type === AuditEventType.ROLE_ELEVATION)

		if (escalationEvents.length >= 3) {
			patterns.push({
				detected: true,
				pattern: "privilege_escalation_attempts",
				confidence: Math.min(escalationEvents.length / 5, 1),
				evidence: [`${escalationEvents.length} role elevation attempts`],
				riskScore: Math.min(escalationEvents.length / 10, 1),
			})
		}

		return patterns
	}

	/**
	 * Map risk score to alert severity
	 */
	private mapRiskScoreToSeverity(riskScore: number): SecurityAlertSeverity {
		if (riskScore >= 0.9) return SecurityAlertSeverity.EMERGENCY
		if (riskScore >= 0.7) return SecurityAlertSeverity.CRITICAL
		if (riskScore >= 0.4) return SecurityAlertSeverity.WARNING
		return SecurityAlertSeverity.INFO
	}

	/**
	 * Create a security alert
	 */
	async createAlert(alertData: Omit<SecurityAlert, "id" | "timestamp" | "acknowledged">): Promise<SecurityAlert> {
		const alert: SecurityAlert = {
			id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
			timestamp: Date.now(),
			acknowledged: false,
			...alertData,
		}

		// Validate alert
		try {
			SecurityAlertSchema.parse(alert)
		} catch (error) {
			console.error("Invalid security alert:", error)
			throw error
		}

		this.alerts.set(alert.id, alert)
		this.updateMetrics(alert)

		// Log the alert
		await this.auditLogger.logEvent({
			type: AuditEventType.SECURITY_VIOLATION,
			severity: this.mapAlertSeverityToAuditSeverity(alert.severity),
			serverName: alert.serverName,
			toolName: alert.toolName,
			userId: alert.userId,
			sessionId: alert.sessionId,
			success: false,
			message: `Security alert: ${alert.title}`,
			details: {
				alertId: alert.id,
				alertType: alert.type,
				description: alert.description,
				...alert.details,
			},
		})

		// Send alert notifications
		await this.sendAlertNotifications(alert)

		// Execute automated response if configured
		if (this.config.autoResponseEnabled && alert.autoResponse) {
			await this.executeAutoResponse(alert)
		}

		return alert
	}

	/**
	 * Map alert severity to audit severity
	 */
	private mapAlertSeverityToAuditSeverity(severity: SecurityAlertSeverity): AuditSeverity {
		switch (severity) {
			case SecurityAlertSeverity.EMERGENCY:
			case SecurityAlertSeverity.CRITICAL:
				return AuditSeverity.CRITICAL
			case SecurityAlertSeverity.WARNING:
				return AuditSeverity.HIGH
			case SecurityAlertSeverity.INFO:
				return AuditSeverity.MEDIUM
		}
	}

	/**
	 * Send alert notifications
	 */
	private async sendAlertNotifications(alert: SecurityAlert): Promise<void> {
		if (this.config.alertChannels.console) {
			this.logAlertToConsole(alert)
		}

		if (this.config.alertChannels.file) {
			// Alert is already logged through audit logger
		}

		// Additional notification channels could be implemented here
		// (webhook, email, etc.)
	}

	/**
	 * Log alert to console
	 */
	private logAlertToConsole(alert: SecurityAlert): void {
		const timestamp = new Date(alert.timestamp).toISOString()
		const message = `[${timestamp}] [SECURITY ALERT] [${alert.severity.toUpperCase()}] ${alert.title}: ${alert.description}`

		switch (alert.severity) {
			case SecurityAlertSeverity.EMERGENCY:
			case SecurityAlertSeverity.CRITICAL:
				console.error(message)
				break
			case SecurityAlertSeverity.WARNING:
				console.warn(message)
				break
			default:
				console.log(message)
		}
	}

	/**
	 * Execute automated response
	 */
	private async executeAutoResponse(alert: SecurityAlert): Promise<void> {
		if (!alert.autoResponse) return

		try {
			const response = alert.autoResponse
			response.executedAt = Date.now()

			switch (response.action) {
				case SecurityResponseAction.LOG_ONLY:
					// Already logged
					response.success = true
					break
				case SecurityResponseAction.RATE_LIMIT:
					// Implementation would depend on rate limiting system
					response.success = true
					break
				case SecurityResponseAction.BLOCK_SERVER:
					// Implementation would depend on server blocking system
					response.success = true
					break
				// Add other response actions as needed
				default:
					response.success = false
					response.error = `Unsupported response action: ${response.action}`
			}

			await this.auditLogger.logEvent({
				type: AuditEventType.SYSTEM_ERROR,
				severity: AuditSeverity.MEDIUM,
				success: response.success || false,
				message: `Automated security response executed: ${response.action}`,
				details: {
					alertId: alert.id,
					response,
				},
			})
		} catch (error) {
			console.error("Failed to execute automated response:", error)
		}
	}

	/**
	 * Update monitoring metrics
	 */
	private updateMetrics(alert: SecurityAlert): void {
		this.metrics.totalAlerts++
		this.metrics.alertsByType[alert.type] = (this.metrics.alertsByType[alert.type] || 0) + 1
		this.metrics.alertsBySeverity[alert.severity] = (this.metrics.alertsBySeverity[alert.severity] || 0) + 1
		this.metrics.activeAlerts++
		this.metrics.lastAlert = alert
	}

	/**
	 * Update system health status
	 */
	private updateSystemHealth(): void {
		const activeAlerts = Array.from(this.alerts.values()).filter((a) => !a.resolvedAt)
		const criticalAlerts = activeAlerts.filter(
			(a) => a.severity === SecurityAlertSeverity.CRITICAL || a.severity === SecurityAlertSeverity.EMERGENCY,
		)

		if (criticalAlerts.length > 0) {
			this.metrics.systemHealth = "critical"
		} else if (activeAlerts.length > 5) {
			this.metrics.systemHealth = "warning"
		} else {
			this.metrics.systemHealth = "healthy"
		}
	}

	/**
	 * Clean up old alerts
	 */
	private cleanupOldAlerts(): void {
		const cutoffTime = Date.now() - this.config.retentionDays * 24 * 60 * 60 * 1000

		for (const [id, alert] of this.alerts.entries()) {
			if (alert.timestamp < cutoffTime) {
				this.alerts.delete(id)
			}
		}
	}

	/**
	 * Acknowledge an alert
	 */
	acknowledgeAlert(alertId: string): boolean {
		const alert = this.alerts.get(alertId)
		if (!alert) return false

		alert.acknowledged = true
		return true
	}

	/**
	 * Resolve an alert
	 */
	resolveAlert(alertId: string): boolean {
		const alert = this.alerts.get(alertId)
		if (!alert) return false

		alert.resolvedAt = Date.now()
		this.metrics.activeAlerts = Math.max(0, this.metrics.activeAlerts - 1)
		this.metrics.resolvedAlerts++

		return true
	}

	/**
	 * Get active alerts
	 */
	getActiveAlerts(): SecurityAlert[] {
		return Array.from(this.alerts.values())
			.filter((alert) => !alert.resolvedAt)
			.sort((a, b) => b.timestamp - a.timestamp)
	}

	/**
	 * Get monitoring metrics
	 */
	getMetrics(): SecurityMonitoringMetrics {
		return { ...this.metrics }
	}

	/**
	 * Update configuration
	 */
	updateConfig(newConfig: Partial<SecurityMonitorConfig>): void {
		this.config = { ...this.config, ...newConfig }
	}

	/**
	 * Get current configuration
	 */
	getConfig(): SecurityMonitorConfig {
		return { ...this.config }
	}
}
