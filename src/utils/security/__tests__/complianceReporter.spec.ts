/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Test suite for ComplianceReporter - compliance reporting and audit trail generation.
 */

import { ComplianceReporter, ComplianceReportType, ReportFormat, ComplianceStandard } from "../complianceReporter"
import { AuditLogger, AuditEventType, AuditSeverity, DEFAULT_AUDIT_CONFIG } from "../auditLogger"
import {
	SecurityMonitor,
	SecurityAlertType,
	SecurityAlertSeverity,
	DEFAULT_SECURITY_MONITOR_CONFIG,
} from "../securityMonitor"
import { SecurityManager, DEFAULT_SECURITY_POLICY } from "../securityUtils"
import * as fs from "fs/promises"
import * as path from "path"

describe("ComplianceReporter", () => {
	let complianceReporter: ComplianceReporter
	let auditLogger: AuditLogger
	let securityMonitor: SecurityMonitor
	let securityManager: SecurityManager
	let tempDir: string

	beforeEach(async () => {
		// Create temporary directory for test files
		tempDir = path.join(__dirname, "temp_compliance_test")
		await fs.mkdir(tempDir, { recursive: true })

		auditLogger = new AuditLogger({
			...DEFAULT_AUDIT_CONFIG,
			logDir: path.join(tempDir, "audit"),
		})
		await auditLogger.initialize()

		securityManager = new SecurityManager(DEFAULT_SECURITY_POLICY)
		securityMonitor = new SecurityMonitor(auditLogger, securityManager, DEFAULT_SECURITY_MONITOR_CONFIG)
		complianceReporter = new ComplianceReporter(auditLogger, securityMonitor, securityManager)
	})

	afterEach(async () => {
		await auditLogger.dispose()
		await securityMonitor.stop()

		// Clean up temporary directory
		try {
			await fs.rm(tempDir, { recursive: true, force: true })
		} catch {
			// Ignore cleanup errors
		}
	})

	describe("report generation", () => {
		it("should generate basic security audit report", async () => {
			// Add some audit events
			await auditLogger.logEvent({
				type: AuditEventType.TOOL_EXECUTION,
				severity: AuditSeverity.LOW,
				serverName: "test_server",
				toolName: "test_tool",
				success: true,
				message: "Test tool execution",
			})

			await auditLogger.logEvent({
				type: AuditEventType.SECURITY_VIOLATION,
				severity: AuditSeverity.HIGH,
				serverName: "test_server",
				success: false,
				message: "Test security violation",
			})

			const config = {
				type: ComplianceReportType.SECURITY_AUDIT,
				format: ReportFormat.JSON,
				timeRange: {
					start: Date.now() - 24 * 60 * 60 * 1000, // 24 hours ago
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			expect(report.metadata).toBeDefined()
			expect(report.metadata.title).toContain("Security Audit")
			expect(report.summary).toBeDefined()
			expect(report.findings).toBeDefined()
			expect(Array.isArray(report.auditTrail)).toBe(true)
			expect(report.metrics).toBeDefined()
		})

		it("should generate SOC2 compliance report", async () => {
			// Add access control events
			await auditLogger.logEvent({
				type: AuditEventType.PERMISSION_DENIED,
				severity: AuditSeverity.MEDIUM,
				serverName: "test_server",
				success: false,
				message: "Access denied",
			})

			const config = {
				type: ComplianceReportType.COMPLIANCE_STATUS,
				format: ReportFormat.JSON,
				standard: ComplianceStandard.SOC2,
				timeRange: {
					start: Date.now() - 7 * 24 * 60 * 60 * 1000, // 7 days ago
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			expect(report.metadata.standard).toBe(ComplianceStandard.SOC2)
			expect(report.metadata.title).toContain("SOC2")
			expect(report.findings.length).toBeGreaterThan(0)
		})

		it("should generate ISO27001 compliance report", async () => {
			// Create security alert
			await securityMonitor.createAlert({
				type: SecurityAlertType.SYSTEM_COMPROMISE,
				severity: SecurityAlertSeverity.CRITICAL,
				title: "Critical Security Incident",
				description: "System compromise detected",
				details: {},
				recommendations: ["Immediate investigation required"],
			})

			const config = {
				type: ComplianceReportType.INCIDENT_REPORT,
				format: ReportFormat.JSON,
				standard: ComplianceStandard.ISO27001,
				timeRange: {
					start: Date.now() - 24 * 60 * 60 * 1000,
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			expect(report.metadata.standard).toBe(ComplianceStandard.ISO27001)
			expect(report.findings.some((f) => f.category === "Incident Management")).toBe(true)
		})

		it("should generate GDPR compliance report", async () => {
			// Add data access events
			for (let i = 0; i < 150; i++) {
				await auditLogger.logEvent({
					type: AuditEventType.RESOURCE_ACCESS,
					severity: AuditSeverity.LOW,
					serverName: "data_server",
					success: true,
					message: `Data access event ${i}`,
				})
			}

			const config = {
				type: ComplianceReportType.COMPLIANCE_STATUS,
				format: ReportFormat.JSON,
				standard: ComplianceStandard.GDPR,
				timeRange: {
					start: Date.now() - 24 * 60 * 60 * 1000,
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			expect(report.metadata.standard).toBe(ComplianceStandard.GDPR)
			expect(report.findings.some((f) => f.category === "Data Protection")).toBe(true)
		})
	})

	describe("report export", () => {
		let testReport: any

		beforeEach(async () => {
			await auditLogger.logEvent({
				type: AuditEventType.TOOL_EXECUTION,
				severity: AuditSeverity.LOW,
				serverName: "test_server",
				success: true,
				message: "Test event",
			})

			const config = {
				type: ComplianceReportType.SECURITY_AUDIT,
				format: ReportFormat.JSON,
				timeRange: {
					start: Date.now() - 24 * 60 * 60 * 1000,
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			testReport = await complianceReporter.generateReport(config)
		})

		it("should export report as JSON", async () => {
			const outputPath = path.join(tempDir, "test_report.json")
			await complianceReporter.exportReport(testReport, ReportFormat.JSON, outputPath)

			const fileExists = await fs
				.access(outputPath)
				.then(() => true)
				.catch(() => false)
			expect(fileExists).toBe(true)

			const content = await fs.readFile(outputPath, "utf-8")
			const parsedReport = JSON.parse(content)
			expect(parsedReport.metadata).toBeDefined()
		})

		it("should export report as CSV", async () => {
			const outputPath = path.join(tempDir, "test_report.csv")
			await complianceReporter.exportReport(testReport, ReportFormat.CSV, outputPath)

			const fileExists = await fs
				.access(outputPath)
				.then(() => true)
				.catch(() => false)
			expect(fileExists).toBe(true)

			const content = await fs.readFile(outputPath, "utf-8")
			expect(content).toContain("Type,Timestamp,Severity,Server,Tool,Message,Success")
		})

		it("should export report as HTML", async () => {
			const outputPath = path.join(tempDir, "test_report.html")
			await complianceReporter.exportReport(testReport, ReportFormat.HTML, outputPath)

			const fileExists = await fs
				.access(outputPath)
				.then(() => true)
				.catch(() => false)
			expect(fileExists).toBe(true)

			const content = await fs.readFile(outputPath, "utf-8")
			expect(content).toContain("<!DOCTYPE html>")
			expect(content).toContain(testReport.metadata.title)
		})

		it("should export report as SIEM format", async () => {
			const outputPath = path.join(tempDir, "test_report.siem")
			await complianceReporter.exportReport(testReport, ReportFormat.SIEM, outputPath)

			const fileExists = await fs
				.access(outputPath)
				.then(() => true)
				.catch(() => false)
			expect(fileExists).toBe(true)

			const content = await fs.readFile(outputPath, "utf-8")
			const lines = content.trim().split("\n")

			// Each line should be valid JSON
			lines.forEach((line) => {
				if (line.trim()) {
					expect(() => JSON.parse(line)).not.toThrow()
				}
			})
		})

		it("should throw error for unsupported format", async () => {
			const outputPath = path.join(tempDir, "test_report.unknown")
			await expect(complianceReporter.exportReport(testReport, "unknown" as any, outputPath)).rejects.toThrow(
				"Unsupported export format",
			)
		})
	})

	describe("security summary", () => {
		it("should calculate compliance score correctly", async () => {
			// Add mix of successful and failed events
			await auditLogger.logEvent({
				type: AuditEventType.TOOL_EXECUTION,
				severity: AuditSeverity.LOW,
				serverName: "test_server",
				success: true,
				message: "Successful event",
			})

			await auditLogger.logEvent({
				type: AuditEventType.SECURITY_VIOLATION,
				severity: AuditSeverity.HIGH,
				serverName: "test_server",
				success: false,
				message: "Security violation",
			})

			const config = {
				type: ComplianceReportType.SECURITY_AUDIT,
				format: ReportFormat.JSON,
				timeRange: {
					start: Date.now() - 24 * 60 * 60 * 1000,
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			expect(report.summary.complianceScore).toBeGreaterThanOrEqual(0)
			expect(report.summary.complianceScore).toBeLessThanOrEqual(1)
			expect(report.summary.totalEvents).toBeGreaterThan(0)
			expect(report.summary.securityViolations).toBeGreaterThan(0)
		})

		it("should assess risk level correctly", async () => {
			// Create critical alert
			await securityMonitor.createAlert({
				type: SecurityAlertType.SYSTEM_COMPROMISE,
				severity: SecurityAlertSeverity.CRITICAL,
				title: "Critical Alert",
				description: "Critical security issue",
				details: {},
				recommendations: [],
			})

			const config = {
				type: ComplianceReportType.RISK_ASSESSMENT,
				format: ReportFormat.JSON,
				timeRange: {
					start: Date.now() - 24 * 60 * 60 * 1000,
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			expect(["low", "medium", "high"]).toContain(report.summary.riskLevel)
			expect(report.summary.criticalAlerts).toBeGreaterThan(0)
		})
	})

	describe("findings generation", () => {
		it("should generate security findings for authentication failures", async () => {
			// Add multiple authentication failures
			for (let i = 0; i < 15; i++) {
				await auditLogger.logEvent({
					type: AuditEventType.AUTHENTICATION_ATTEMPT,
					severity: AuditSeverity.MEDIUM,
					serverName: "auth_server",
					success: false,
					message: `Authentication failed ${i}`,
				})
			}

			const config = {
				type: ComplianceReportType.SECURITY_AUDIT,
				format: ReportFormat.JSON,
				timeRange: {
					start: Date.now() - 24 * 60 * 60 * 1000,
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			const authFindings = report.findings.filter((f) => f.category === "Authentication")
			expect(authFindings.length).toBeGreaterThan(0)
			expect(authFindings[0].severity).toBe("high")
		})

		it("should generate access control findings", async () => {
			// Add many auto-granted permissions
			for (let i = 0; i < 60; i++) {
				await auditLogger.logEvent({
					type: AuditEventType.PERMISSION_GRANTED,
					severity: AuditSeverity.LOW,
					serverName: "test_server",
					success: true,
					message: "Permission auto-granted",
					details: { autoGranted: true },
				})
			}

			const config = {
				type: ComplianceReportType.ACCESS_CONTROL,
				format: ReportFormat.JSON,
				timeRange: {
					start: Date.now() - 24 * 60 * 60 * 1000,
					end: Date.now(),
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			const accessFindings = report.findings.filter((f) => f.category === "Access Control")
			expect(accessFindings.length).toBeGreaterThan(0)
		})
	})

	describe("report validation", () => {
		it("should validate report configuration", async () => {
			const invalidConfig = {
				type: "invalid_type" as any,
				format: ReportFormat.JSON,
				timeRange: {
					start: Date.now(),
					end: Date.now() - 1000, // Invalid: end before start
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			await expect(complianceReporter.generateReport(invalidConfig)).rejects.toThrow()
		})

		it("should handle empty time ranges", async () => {
			const config = {
				type: ComplianceReportType.SECURITY_AUDIT,
				format: ReportFormat.JSON,
				timeRange: {
					start: Date.now() + 24 * 60 * 60 * 1000, // Future start time
					end: Date.now() + 48 * 60 * 60 * 1000, // Future end time
				},
				includeDetails: true,
				includeSensitiveData: false,
			}

			const report = await complianceReporter.generateReport(config)

			expect(report.summary.totalEvents).toBe(0)
			expect(report.auditTrail).toHaveLength(0)
		})
	})
})
