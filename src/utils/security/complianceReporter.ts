/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Compliance reporting and audit trail generation for MCP security operations.
 * Provides standardized reporting formats for security audits and compliance requirements.
 */

import { z } from "zod"
import * as fs from "fs/promises"
import * as path from "path"
import { AuditLogger, AuditEvent, AuditEventType, AuditSeverity, AuditStatistics } from "./auditLogger"
import { SecurityMonitor, SecurityAlert, SecurityAlertType, SecurityAlertSeverity } from "./securityMonitor"
import { SecurityManager, SecurityMetrics } from "./securityUtils"

/**
 * Compliance report types
 */
export enum ComplianceReportType {
	SECURITY_AUDIT = "security_audit",
	ACCESS_CONTROL = "access_control",
	VIOLATION_SUMMARY = "violation_summary",
	SYSTEM_HEALTH = "system_health",
	RISK_ASSESSMENT = "risk_assessment",
	INCIDENT_REPORT = "incident_report",
	COMPLIANCE_STATUS = "compliance_status",
}

/**
 * Report output formats
 */
export enum ReportFormat {
	JSON = "json",
	CSV = "csv",
	HTML = "html",
	PDF = "pdf",
	SIEM = "siem",
}

/**
 * Compliance standards
 */
export enum ComplianceStandard {
	SOC2 = "soc2",
	ISO27001 = "iso27001",
	GDPR = "gdpr",
	HIPAA = "hipaa",
	PCI_DSS = "pci_dss",
	NIST = "nist",
	CUSTOM = "custom",
}

/**
 * Compliance report configuration
 */
export interface ComplianceReportConfig {
	type: ComplianceReportType
	format: ReportFormat
	standard?: ComplianceStandard
	timeRange: {
		start: number
		end: number
	}
	includeDetails: boolean
	includeSensitiveData: boolean
	outputPath?: string
	customFields?: Record<string, unknown>
}

/**
 * Compliance report metadata
 */
export interface ComplianceReportMetadata {
	id: string
	title: string
	description: string
	generatedAt: number
	generatedBy?: string
	version: string
	standard?: ComplianceStandard
	timeRange: {
		start: number
		end: number
	}
	dataIntegrity: {
		checksum: string
		eventCount: number
		alertCount: number
	}
}

/**
 * Security summary for compliance reports
 */
export interface SecuritySummary {
	totalEvents: number
	securityViolations: number
	criticalAlerts: number
	systemHealth: "healthy" | "warning" | "critical"
	complianceScore: number
	riskLevel: "low" | "medium" | "high"
	recommendations: string[]
}

/**
 * Compliance finding
 */
export interface ComplianceFinding {
	id: string
	severity: "low" | "medium" | "high" | "critical"
	category: string
	title: string
	description: string
	evidence: string[]
	recommendation: string
	status: "open" | "acknowledged" | "resolved"
	assignedTo?: string
	dueDate?: number
}

/**
 * Compliance report structure
 */
export interface ComplianceReport {
	metadata: ComplianceReportMetadata
	summary: SecuritySummary
	findings: ComplianceFinding[]
	auditTrail: AuditEvent[]
	securityAlerts: SecurityAlert[]
	metrics: {
		security: SecurityMetrics
		audit: AuditStatistics
	}
	appendices?: {
		rawData?: unknown
		configurations?: unknown
		policies?: unknown
	}
}

/**
 * Zod schemas
 */
export const ComplianceReportTypeSchema = z.nativeEnum(ComplianceReportType)
export const ReportFormatSchema = z.nativeEnum(ReportFormat)
export const ComplianceStandardSchema = z.nativeEnum(ComplianceStandard)

export const ComplianceReportConfigSchema = z.object({
	type: ComplianceReportTypeSchema,
	format: ReportFormatSchema,
	standard: ComplianceStandardSchema.optional(),
	timeRange: z.object({
		start: z.number(),
		end: z.number(),
	}),
	includeDetails: z.boolean(),
	includeSensitiveData: z.boolean(),
	outputPath: z.string().optional(),
	customFields: z.record(z.unknown()).optional(),
})

export const ComplianceFindingSchema = z.object({
	id: z.string(),
	severity: z.enum(["low", "medium", "high", "critical"]),
	category: z.string(),
	title: z.string(),
	description: z.string(),
	evidence: z.array(z.string()),
	recommendation: z.string(),
	status: z.enum(["open", "acknowledged", "resolved"]),
	assignedTo: z.string().optional(),
	dueDate: z.number().optional(),
})

/**
 * Compliance reporter implementation
 */
export class ComplianceReporter {
	private auditLogger: AuditLogger
	private securityMonitor: SecurityMonitor
	private securityManager: SecurityManager

	constructor(auditLogger: AuditLogger, securityMonitor: SecurityMonitor, securityManager: SecurityManager) {
		this.auditLogger = auditLogger
		this.securityMonitor = securityMonitor
		this.securityManager = securityManager
	}

	/**
	 * Generate compliance report
	 */
	async generateReport(config: ComplianceReportConfig): Promise<ComplianceReport> {
		// Validate configuration
		ComplianceReportConfigSchema.parse(config)

		// Collect data for the report
		const auditEvents = await this.auditLogger.queryEvents({
			startTime: config.timeRange.start,
			endTime: config.timeRange.end,
		})

		const auditStatistics = await this.auditLogger.getStatistics(config.timeRange)
		const securityMetrics = this.securityManager.getMetrics()
		const securityAlerts = this.securityMonitor.getActiveAlerts()

		// Generate report metadata
		const metadata = this.generateMetadata(config, auditEvents, securityAlerts)

		// Generate security summary
		const summary = this.generateSecuritySummary(auditEvents, securityAlerts, securityMetrics)

		// Generate compliance findings
		const findings = await this.generateFindings(config, auditEvents, securityAlerts)

		// Create the report
		const report: ComplianceReport = {
			metadata,
			summary,
			findings,
			auditTrail: config.includeDetails ? auditEvents : [],
			securityAlerts: config.includeDetails ? securityAlerts : [],
			metrics: {
				security: securityMetrics,
				audit: auditStatistics,
			},
		}

		// Add appendices if requested
		if (config.includeDetails) {
			report.appendices = {
				rawData: {
					events: auditEvents.length,
					alerts: securityAlerts.length,
				},
			}
		}

		return report
	}

	/**
	 * Generate report metadata
	 */
	private generateMetadata(
		config: ComplianceReportConfig,
		auditEvents: AuditEvent[],
		securityAlerts: SecurityAlert[],
	): ComplianceReportMetadata {
		const checksum = this.calculateDataChecksum(auditEvents, securityAlerts)

		return {
			id: `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
			title: this.getReportTitle(config.type, config.standard),
			description: this.getReportDescription(config.type, config.timeRange),
			generatedAt: Date.now(),
			version: "1.0.0",
			standard: config.standard,
			timeRange: config.timeRange,
			dataIntegrity: {
				checksum,
				eventCount: auditEvents.length,
				alertCount: securityAlerts.length,
			},
		}
	}

	/**
	 * Generate security summary
	 */
	private generateSecuritySummary(
		auditEvents: AuditEvent[],
		securityAlerts: SecurityAlert[],
		securityMetrics: SecurityMetrics,
	): SecuritySummary {
		const securityViolations = auditEvents.filter((e) => e.type === AuditEventType.SECURITY_VIOLATION).length

		const criticalAlerts = securityAlerts.filter(
			(a) => a.severity === SecurityAlertSeverity.CRITICAL || a.severity === SecurityAlertSeverity.EMERGENCY,
		).length

		const complianceScore = this.calculateComplianceScore(auditEvents, securityAlerts)
		const riskLevel = this.assessOverallRiskLevel(auditEvents, securityAlerts)
		const systemHealth = this.assessSystemHealth(securityViolations, criticalAlerts)

		return {
			totalEvents: auditEvents.length,
			securityViolations,
			criticalAlerts,
			systemHealth,
			complianceScore,
			riskLevel,
			recommendations: this.generateRecommendations(riskLevel, securityViolations, criticalAlerts),
		}
	}

	/**
	 * Generate compliance findings
	 */
	private async generateFindings(
		config: ComplianceReportConfig,
		auditEvents: AuditEvent[],
		securityAlerts: SecurityAlert[],
	): Promise<ComplianceFinding[]> {
		const findings: ComplianceFinding[] = []

		// Generate findings based on compliance standard
		if (config.standard) {
			findings.push(...this.generateStandardSpecificFindings(config.standard, auditEvents, securityAlerts))
		}

		// Generate general security findings
		findings.push(...this.generateSecurityFindings(auditEvents, securityAlerts))

		// Generate access control findings
		findings.push(...this.generateAccessControlFindings(auditEvents))

		return findings
	}

	/**
	 * Generate standard-specific findings
	 */
	private generateStandardSpecificFindings(
		standard: ComplianceStandard,
		auditEvents: AuditEvent[],
		securityAlerts: SecurityAlert[],
	): ComplianceFinding[] {
		const findings: ComplianceFinding[] = []

		switch (standard) {
			case ComplianceStandard.SOC2:
				findings.push(...this.generateSOC2Findings(auditEvents, securityAlerts))
				break
			case ComplianceStandard.ISO27001:
				findings.push(...this.generateISO27001Findings(auditEvents, securityAlerts))
				break
			case ComplianceStandard.GDPR:
				findings.push(...this.generateGDPRFindings(auditEvents, securityAlerts))
				break
			// Add other standards as needed
		}

		return findings
	}

	/**
	 * Generate SOC2 specific findings
	 */
	private generateSOC2Findings(auditEvents: AuditEvent[], securityAlerts: SecurityAlert[]): ComplianceFinding[] {
		const findings: ComplianceFinding[] = []

		// Check for proper access controls
		const accessViolations = auditEvents.filter((e) => e.type === AuditEventType.PERMISSION_DENIED)

		if (accessViolations.length > 0) {
			findings.push({
				id: `soc2_access_${Date.now()}`,
				severity: "medium",
				category: "Access Control",
				title: "Access Control Violations Detected",
				description: `${accessViolations.length} access control violations found`,
				evidence: accessViolations.slice(0, 5).map((e) => e.message),
				recommendation: "Review and strengthen access control policies",
				status: "open",
			})
		}

		// Check for monitoring and logging
		const monitoringGaps = this.checkMonitoringGaps(auditEvents)
		if (monitoringGaps.length > 0) {
			findings.push({
				id: `soc2_monitoring_${Date.now()}`,
				severity: "high",
				category: "Monitoring",
				title: "Monitoring Gaps Identified",
				description: "Gaps in security monitoring coverage detected",
				evidence: monitoringGaps,
				recommendation: "Implement comprehensive monitoring for all critical systems",
				status: "open",
			})
		}

		return findings
	}

	/**
	 * Generate ISO27001 specific findings
	 */
	private generateISO27001Findings(auditEvents: AuditEvent[], securityAlerts: SecurityAlert[]): ComplianceFinding[] {
		const findings: ComplianceFinding[] = []

		// Check for information security incidents
		const securityIncidents = securityAlerts.filter(
			(a) => a.severity === SecurityAlertSeverity.CRITICAL || a.severity === SecurityAlertSeverity.EMERGENCY,
		)

		if (securityIncidents.length > 0) {
			findings.push({
				id: `iso27001_incidents_${Date.now()}`,
				severity: "critical",
				category: "Incident Management",
				title: "Security Incidents Require Review",
				description: `${securityIncidents.length} critical security incidents detected`,
				evidence: securityIncidents.map((i) => i.title),
				recommendation: "Conduct formal incident response and root cause analysis",
				status: "open",
			})
		}

		return findings
	}

	/**
	 * Generate GDPR specific findings
	 */
	private generateGDPRFindings(auditEvents: AuditEvent[], securityAlerts: SecurityAlert[]): ComplianceFinding[] {
		const findings: ComplianceFinding[] = []

		// Check for data access events
		const dataAccessEvents = auditEvents.filter((e) => e.type === AuditEventType.RESOURCE_ACCESS)

		if (dataAccessEvents.length > 100) {
			findings.push({
				id: `gdpr_data_access_${Date.now()}`,
				severity: "medium",
				category: "Data Protection",
				title: "High Volume of Data Access Events",
				description: `${dataAccessEvents.length} data access events recorded`,
				evidence: ["High volume of data access may indicate data processing activities"],
				recommendation: "Review data access patterns for GDPR compliance",
				status: "open",
			})
		}

		return findings
	}

	/**
	 * Generate general security findings
	 */
	private generateSecurityFindings(auditEvents: AuditEvent[], securityAlerts: SecurityAlert[]): ComplianceFinding[] {
		const findings: ComplianceFinding[] = []

		// Check for failed authentication attempts
		const authFailures = auditEvents.filter((e) => e.type === AuditEventType.AUTHENTICATION_ATTEMPT && !e.success)

		if (authFailures.length >= 10) {
			findings.push({
				id: `security_auth_failures_${Date.now()}`,
				severity: "high",
				category: "Authentication",
				title: "Multiple Authentication Failures",
				description: `${authFailures.length} failed authentication attempts detected`,
				evidence: authFailures.slice(0, 3).map((e) => e.message),
				recommendation: "Investigate potential brute force attacks and implement account lockout policies",
				status: "open",
			})
		}

		// Check for privilege escalation
		const privilegeEscalation = auditEvents.filter((e) => e.type === AuditEventType.ROLE_ELEVATION)

		if (privilegeEscalation.length > 0) {
			findings.push({
				id: `security_privilege_escalation_${Date.now()}`,
				severity: "medium",
				category: "Privilege Management",
				title: "Privilege Escalation Events",
				description: `${privilegeEscalation.length} privilege escalation events recorded`,
				evidence: privilegeEscalation.map((e) => e.message),
				recommendation: "Review privilege escalation procedures and ensure proper authorization",
				status: "open",
			})
		}

		return findings
	}

	/**
	 * Generate access control findings
	 */
	private generateAccessControlFindings(auditEvents: AuditEvent[]): ComplianceFinding[] {
		const findings: ComplianceFinding[] = []

		// Check for permission grants without approval
		const autoGrantedPermissions = auditEvents.filter(
			(e) => e.type === AuditEventType.PERMISSION_GRANTED && e.details?.autoGranted === true,
		)

		if (autoGrantedPermissions.length > 50) {
			findings.push({
				id: `access_auto_grants_${Date.now()}`,
				severity: "medium",
				category: "Access Control",
				title: "High Number of Auto-Granted Permissions",
				description: `${autoGrantedPermissions.length} permissions were automatically granted`,
				evidence: ["High volume of auto-granted permissions may indicate overly permissive policies"],
				recommendation:
					"Review auto-grant policies and consider requiring manual approval for sensitive operations",
				status: "open",
			})
		}

		return findings
	}

	/**
	 * Export report in specified format
	 */
	async exportReport(report: ComplianceReport, format: ReportFormat, outputPath: string): Promise<void> {
		switch (format) {
			case ReportFormat.JSON:
				await this.exportAsJSON(report, outputPath)
				break
			case ReportFormat.CSV:
				await this.exportAsCSV(report, outputPath)
				break
			case ReportFormat.HTML:
				await this.exportAsHTML(report, outputPath)
				break
			case ReportFormat.SIEM:
				await this.exportAsSIEM(report, outputPath)
				break
			default:
				throw new Error(`Unsupported export format: ${format}`)
		}
	}

	/**
	 * Export as JSON
	 */
	private async exportAsJSON(report: ComplianceReport, outputPath: string): Promise<void> {
		const jsonContent = JSON.stringify(report, null, 2)
		await fs.writeFile(outputPath, jsonContent, "utf-8")
	}

	/**
	 * Export as CSV
	 */
	private async exportAsCSV(report: ComplianceReport, outputPath: string): Promise<void> {
		const csvLines: string[] = []

		// Header
		csvLines.push("Type,Timestamp,Severity,Server,Tool,Message,Success")

		// Audit events
		for (const event of report.auditTrail) {
			const line = [
				event.type,
				new Date(event.timestamp).toISOString(),
				event.severity,
				event.serverName || "",
				event.toolName || "",
				`"${event.message.replace(/"/g, '""')}"`,
				event.success.toString(),
			].join(",")
			csvLines.push(line)
		}

		await fs.writeFile(outputPath, csvLines.join("\n"), "utf-8")
	}

	/**
	 * Export as HTML
	 */
	private async exportAsHTML(report: ComplianceReport, outputPath: string): Promise<void> {
		const html = this.generateHTMLReport(report)
		await fs.writeFile(outputPath, html, "utf-8")
	}

	/**
	 * Export as SIEM format
	 */
	private async exportAsSIEM(report: ComplianceReport, outputPath: string): Promise<void> {
		const siemEvents = report.auditTrail.map((event) => ({
			timestamp: new Date(event.timestamp).toISOString(),
			event_type: event.type,
			severity: event.severity,
			source: event.serverName || "unknown",
			message: event.message,
			details: event.details,
		}))

		const siemContent = siemEvents.map((event) => JSON.stringify(event)).join("\n")
		await fs.writeFile(outputPath, siemContent, "utf-8")
	}

	/**
	 * Generate HTML report
	 */
	private generateHTMLReport(report: ComplianceReport): string {
		return `
<!DOCTYPE html>
<html>
<head>
    <title>${report.metadata.title}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .findings { margin: 20px 0; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .finding.critical { border-left: 5px solid #d32f2f; }
        .finding.high { border-left: 5px solid #f57c00; }
        .finding.medium { border-left: 5px solid #fbc02d; }
        .finding.low { border-left: 5px solid #388e3c; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .metric { background: #f9f9f9; padding: 15px; border-radius: 5px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>${report.metadata.title}</h1>
        <p><strong>Generated:</strong> ${new Date(report.metadata.generatedAt).toLocaleString()}</p>
        <p><strong>Period:</strong> ${new Date(report.metadata.timeRange.start).toLocaleDateString()} - ${new Date(report.metadata.timeRange.end).toLocaleDateString()}</p>
        ${report.metadata.standard ? `<p><strong>Standard:</strong> ${report.metadata.standard.toUpperCase()}</p>` : ""}
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="metrics">
            <div class="metric">
                <h3>${report.summary.totalEvents}</h3>
                <p>Total Events</p>
            </div>
            <div class="metric">
                <h3>${report.summary.securityViolations}</h3>
                <p>Security Violations</p>
            </div>
            <div class="metric">
                <h3>${report.summary.criticalAlerts}</h3>
                <p>Critical Alerts</p>
            </div>
            <div class="metric">
                <h3>${(report.summary.complianceScore * 100).toFixed(1)}%</h3>
                <p>Compliance Score</p>
            </div>
        </div>
        <p><strong>System Health:</strong> ${report.summary.systemHealth}</p>
        <p><strong>Risk Level:</strong> ${report.summary.riskLevel}</p>
    </div>

    <div class="findings">
        <h2>Findings (${report.findings.length})</h2>
        ${report.findings
			.map(
				(finding) => `
            <div class="finding ${finding.severity}">
                <h3>${finding.title}</h3>
                <p><strong>Severity:</strong> ${finding.severity.toUpperCase()}</p>
                <p><strong>Category:</strong> ${finding.category}</p>
                <p>${finding.description}</p>
                <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
            </div>
        `,
			)
			.join("")}
    </div>
</body>
</html>`
	}

	/**
	 * Helper methods
	 */
	private calculateDataChecksum(auditEvents: AuditEvent[], securityAlerts: SecurityAlert[]): string {
		const data = JSON.stringify({ events: auditEvents.length, alerts: securityAlerts.length })
		// Simple checksum - in production, use a proper hash function
		return Buffer.from(data).toString("base64").slice(0, 16)
	}

	private getReportTitle(type: ComplianceReportType, standard?: ComplianceStandard): string {
		const baseTitle = type.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())
		return standard ? `${baseTitle} - ${standard.toUpperCase()} Compliance` : baseTitle
	}

	private getReportDescription(type: ComplianceReportType, timeRange: { start: number; end: number }): string {
		const startDate = new Date(timeRange.start).toLocaleDateString()
		const endDate = new Date(timeRange.end).toLocaleDateString()
		return `${type.replace(/_/g, " ")} report covering the period from ${startDate} to ${endDate}`
	}

	private calculateComplianceScore(auditEvents: AuditEvent[], securityAlerts: SecurityAlert[]): number {
		const totalEvents = auditEvents.length
		const violations = auditEvents.filter((e) => e.type === AuditEventType.SECURITY_VIOLATION).length
		const criticalAlerts = securityAlerts.filter(
			(a) => a.severity === SecurityAlertSeverity.CRITICAL || a.severity === SecurityAlertSeverity.EMERGENCY,
		).length

		if (totalEvents === 0) return 1.0

		const violationRate = violations / totalEvents
		const alertPenalty = Math.min(criticalAlerts * 0.1, 0.5)

		return Math.max(0, 1.0 - violationRate - alertPenalty)
	}

	private assessOverallRiskLevel(
		auditEvents: AuditEvent[],
		securityAlerts: SecurityAlert[],
	): "low" | "medium" | "high" {
		const criticalAlerts = securityAlerts.filter(
			(a) => a.severity === SecurityAlertSeverity.CRITICAL || a.severity === SecurityAlertSeverity.EMERGENCY,
		).length

		const violations = auditEvents.filter((e) => e.type === AuditEventType.SECURITY_VIOLATION).length

		if (criticalAlerts > 0 || violations > 20) return "high"
		if (violations > 5) return "medium"
		return "low"
	}

	private assessSystemHealth(violations: number, criticalAlerts: number): "healthy" | "warning" | "critical" {
		if (criticalAlerts > 0) return "critical"
		if (violations > 10) return "warning"
		return "healthy"
	}

	private generateRecommendations(riskLevel: string, violations: number, criticalAlerts: number): string[] {
		const recommendations: string[] = []

		if (riskLevel === "high") {
			recommendations.push("Immediate security review required")
			recommendations.push("Implement additional monitoring controls")
		}

		if (violations > 10) {
			recommendations.push("Review and strengthen security policies")
			recommendations.push("Provide additional security training")
		}

		if (criticalAlerts > 0) {
			recommendations.push("Address all critical security alerts immediately")
			recommendations.push("Conduct incident response procedures")
		}

		if (recommendations.length === 0) {
			recommendations.push("Continue current security practices")
			recommendations.push("Regular security reviews recommended")
		}

		return recommendations
	}

	private checkMonitoringGaps(auditEvents: AuditEvent[]): string[] {
		const gaps: string[] = []

		// Check for gaps in event types
		const eventTypes = new Set(auditEvents.map((e) => e.type))
		const expectedTypes = Object.values(AuditEventType)

		for (const expectedType of expectedTypes) {
			if (!eventTypes.has(expectedType)) {
				gaps.push(`No ${expectedType} events recorded`)
			}
		}

		return gaps
	}
}
