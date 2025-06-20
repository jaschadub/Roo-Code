/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Comprehensive security integration example showing how to use all security components together.
 * This demonstrates the complete audit logging and monitoring system for MCP operations.
 */

import {
	AuditLogger,
	SecurityMonitor,
	ComplianceReporter,
	AnomalyDetector,
	SecurityManager,
	PermissionManager,
	AccessControlManager,
	AuditEventType,
	AuditSeverity,
	SecurityAlertType,
	SecurityAlertSeverity,
	ComplianceReportType,
	ReportFormat,
	ComplianceStandard,
	DEFAULT_AUDIT_CONFIG,
	DEFAULT_SECURITY_MONITOR_CONFIG,
	DEFAULT_ANOMALY_DETECTOR_CONFIG,
	DEFAULT_SECURITY_POLICY,
	DEFAULT_PERMISSION_POLICY,
	DEFAULT_ACCESS_CONTROL_POLICY,
} from "./index"

/**
 * Comprehensive security system that integrates all security components
 */
export class ComprehensiveSecuritySystem {
	private auditLogger: AuditLogger
	private securityMonitor: SecurityMonitor
	private complianceReporter: ComplianceReporter
	private anomalyDetector: AnomalyDetector
	private securityManager: SecurityManager
	private permissionManager: PermissionManager
	private accessControlManager: AccessControlManager

	constructor() {
		// Initialize core components
		this.auditLogger = new AuditLogger(DEFAULT_AUDIT_CONFIG)
		this.securityManager = new SecurityManager(DEFAULT_SECURITY_POLICY)
		this.permissionManager = new PermissionManager(DEFAULT_PERMISSION_POLICY)
		this.accessControlManager = new AccessControlManager(this.permissionManager, DEFAULT_ACCESS_CONTROL_POLICY)

		// Initialize monitoring and analysis components
		this.securityMonitor = new SecurityMonitor(
			this.auditLogger,
			this.securityManager,
			DEFAULT_SECURITY_MONITOR_CONFIG,
		)
		this.anomalyDetector = new AnomalyDetector(DEFAULT_ANOMALY_DETECTOR_CONFIG)
		this.complianceReporter = new ComplianceReporter(this.auditLogger, this.securityMonitor, this.securityManager)
	}

	/**
	 * Initialize the complete security system
	 */
	async initialize(): Promise<void> {
		await this.auditLogger.initialize()
		await this.securityMonitor.start()
		await this.anomalyDetector.start()

		// Log system initialization
		await this.auditLogger.logEvent({
			type: AuditEventType.SYSTEM_ERROR,
			severity: AuditSeverity.LOW,
			success: true,
			message: "Comprehensive security system initialized",
			details: {
				components: [
					"AuditLogger",
					"SecurityMonitor",
					"ComplianceReporter",
					"AnomalyDetector",
					"SecurityManager",
					"PermissionManager",
					"AccessControlManager",
				],
			},
		})
	}

	/**
	 * Log MCP tool execution with comprehensive security context
	 */
	async logMcpToolExecution(
		serverName: string,
		toolName: string,
		arguments_: Record<string, unknown>,
		success: boolean,
		userId?: string,
		sessionId?: string,
	): Promise<void> {
		// Log the execution
		await this.auditLogger.logEvent({
			type: AuditEventType.TOOL_EXECUTION,
			severity: success ? AuditSeverity.LOW : AuditSeverity.MEDIUM,
			serverName,
			toolName,
			userId,
			sessionId,
			success,
			message: `MCP tool ${toolName} execution ${success ? "succeeded" : "failed"}`,
			details: {
				arguments: arguments_,
				timestamp: Date.now(),
			},
		})

		// Check for anomalies in recent events
		const recentEvents = await this.auditLogger.queryEvents({
			startTime: Date.now() - 60 * 60 * 1000, // Last hour
			serverNames: [serverName],
			limit: 100,
		})

		const anomalies = await this.anomalyDetector.analyzeEvents(recentEvents)

		// Create alerts for detected anomalies
		for (const anomaly of anomalies) {
			await this.securityMonitor.createAlert({
				type: SecurityAlertType.ANOMALY_DETECTED,
				severity: this.mapAnomalySeverityToAlertSeverity(anomaly.severity),
				title: `Anomaly Detected: ${anomaly.description}`,
				description: anomaly.description,
				serverName,
				toolName,
				userId,
				sessionId,
				details: {
					anomalyId: anomaly.id,
					anomalyType: anomaly.type,
					confidence: anomaly.confidence,
					riskScore: anomaly.riskScore,
					evidence: anomaly.evidence,
				},
				recommendations: anomaly.recommendations,
			})
		}
	}

	/**
	 * Generate comprehensive security report
	 */
	async generateSecurityReport(
		timeRange: { start: number; end: number },
		standard?: ComplianceStandard,
		format: ReportFormat = ReportFormat.JSON,
	): Promise<string> {
		const report = await this.complianceReporter.generateReport({
			type: ComplianceReportType.SECURITY_AUDIT,
			format,
			standard,
			timeRange,
			includeDetails: true,
			includeSensitiveData: false,
		})

		// Export to temporary file and return path
		const outputPath = `/tmp/security_report_${Date.now()}.${format.toLowerCase()}`
		await this.complianceReporter.exportReport(report, format, outputPath)

		// Log report generation
		await this.auditLogger.logEvent({
			type: AuditEventType.SYSTEM_ERROR,
			severity: AuditSeverity.LOW,
			success: true,
			message: "Security report generated",
			details: {
				reportType: ComplianceReportType.SECURITY_AUDIT,
				format,
				standard,
				timeRange,
				outputPath,
				totalEvents: report.summary.totalEvents,
				securityViolations: report.summary.securityViolations,
				complianceScore: report.summary.complianceScore,
			},
		})

		return outputPath
	}

	/**
	 * Get comprehensive security metrics
	 */
	async getSecurityMetrics(): Promise<{
		audit: any
		security: any
		monitoring: any
		anomalies: any
		permissions: any
	}> {
		const auditStats = await this.auditLogger.getStatistics()
		const securityMetrics = this.securityManager.getMetrics()
		const monitoringMetrics = this.securityMonitor.getMetrics()
		const anomalyResults = this.anomalyDetector.getDetectionResults()
		const activeAlerts = this.securityMonitor.getActiveAlerts()

		return {
			audit: auditStats,
			security: securityMetrics,
			monitoring: monitoringMetrics,
			anomalies: {
				totalDetections: anomalyResults.length,
				recentDetections: anomalyResults.slice(0, 10),
				detectionsByType: anomalyResults.reduce(
					(acc, result) => {
						acc[result.type] = (acc[result.type] || 0) + 1
						return acc
					},
					{} as Record<string, number>,
				),
			},
			permissions: {
				activeAlerts: activeAlerts.length,
				criticalAlerts: activeAlerts.filter(
					(a) =>
						a.severity === SecurityAlertSeverity.CRITICAL || a.severity === SecurityAlertSeverity.EMERGENCY,
				).length,
				systemHealth: monitoringMetrics.systemHealth,
			},
		}
	}

	/**
	 * Perform comprehensive security check
	 */
	async performSecurityCheck(): Promise<{
		status: "healthy" | "warning" | "critical"
		issues: string[]
		recommendations: string[]
	}> {
		const metrics = await this.getSecurityMetrics()
		const issues: string[] = []
		const recommendations: string[] = []
		let status: "healthy" | "warning" | "critical" = "healthy"

		// Check for critical alerts
		if (metrics.permissions.criticalAlerts > 0) {
			status = "critical"
			issues.push(`${metrics.permissions.criticalAlerts} critical security alerts active`)
			recommendations.push("Investigate and resolve critical security alerts immediately")
		}

		// Check violation rates
		if (metrics.security.totalViolations > 0) {
			const violationRate = metrics.security.totalViolations / metrics.security.totalValidations
			if (violationRate > 0.1) {
				status = status === "healthy" ? "warning" : status
				issues.push(`High security violation rate: ${(violationRate * 100).toFixed(1)}%`)
				recommendations.push("Review security policies and investigate violation patterns")
			}
		}

		// Check for recent anomalies
		if (metrics.anomalies.totalDetections > 0) {
			const recentAnomalies = metrics.anomalies.recentDetections.filter(
				(a: any) => a.timestamp > Date.now() - 24 * 60 * 60 * 1000,
			)
			if (recentAnomalies.length > 5) {
				status = status === "healthy" ? "warning" : status
				issues.push(`${recentAnomalies.length} anomalies detected in the last 24 hours`)
				recommendations.push("Investigate recent anomalous activity patterns")
			}
		}

		// Check system health
		if (metrics.monitoring.systemHealth === "critical") {
			status = "critical"
			issues.push("System health status is critical")
			recommendations.push("Immediate system investigation required")
		} else if (metrics.monitoring.systemHealth === "warning") {
			status = status === "healthy" ? "warning" : status
			issues.push("System health status shows warnings")
			recommendations.push("Monitor system closely and investigate warnings")
		}

		if (issues.length === 0) {
			recommendations.push("System security status is healthy")
			recommendations.push("Continue regular monitoring and maintenance")
		}

		return { status, issues, recommendations }
	}

	/**
	 * Shutdown the security system
	 */
	async shutdown(): Promise<void> {
		await this.auditLogger.logEvent({
			type: AuditEventType.SYSTEM_ERROR,
			severity: AuditSeverity.LOW,
			success: true,
			message: "Comprehensive security system shutting down",
		})

		await this.securityMonitor.stop()
		await this.anomalyDetector.stop()
		await this.auditLogger.dispose()
	}

	/**
	 * Helper method to map anomaly severity to alert severity
	 */
	private mapAnomalySeverityToAlertSeverity(severity: "low" | "medium" | "high" | "critical"): SecurityAlertSeverity {
		switch (severity) {
			case "critical":
				return SecurityAlertSeverity.CRITICAL
			case "high":
				return SecurityAlertSeverity.WARNING
			case "medium":
				return SecurityAlertSeverity.WARNING
			case "low":
			default:
				return SecurityAlertSeverity.INFO
		}
	}
}

/**
 * Example usage of the comprehensive security system
 */
export async function exampleUsage(): Promise<void> {
	const securitySystem = new ComprehensiveSecuritySystem()

	try {
		// Initialize the system
		await securitySystem.initialize()

		// Log some MCP operations
		await securitySystem.logMcpToolExecution(
			"example_server",
			"example_tool",
			{ param1: "value1", param2: "value2" },
			true,
			"user123",
			"session456",
		)

		// Perform security check
		const securityCheck = await securitySystem.performSecurityCheck()
		console.log("Security Status:", securityCheck.status)
		console.log("Issues:", securityCheck.issues)
		console.log("Recommendations:", securityCheck.recommendations)

		// Generate security report
		const reportPath = await securitySystem.generateSecurityReport(
			{
				start: Date.now() - 24 * 60 * 60 * 1000, // Last 24 hours
				end: Date.now(),
			},
			ComplianceStandard.SOC2,
			ReportFormat.HTML,
		)
		console.log("Security report generated:", reportPath)

		// Get comprehensive metrics
		const metrics = await securitySystem.getSecurityMetrics()
		console.log("Security Metrics:", JSON.stringify(metrics, null, 2))
	} finally {
		// Always shutdown properly
		await securitySystem.shutdown()
	}
}
