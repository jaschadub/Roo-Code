/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Test suite for SecurityMonitor - real-time security monitoring and alerting.
 */

import {
	SecurityMonitor,
	SecurityAlertType,
	SecurityAlertSeverity,
	DEFAULT_SECURITY_MONITOR_CONFIG,
} from "../securityMonitor"
import { AuditLogger, AuditEventType, AuditSeverity, DEFAULT_AUDIT_CONFIG } from "../auditLogger"
import { SecurityManager, DEFAULT_SECURITY_POLICY } from "../securityUtils"

describe("SecurityMonitor", () => {
	let securityMonitor: SecurityMonitor
	let auditLogger: AuditLogger
	let securityManager: SecurityManager

	beforeEach(async () => {
		auditLogger = new AuditLogger(DEFAULT_AUDIT_CONFIG)
		await auditLogger.initialize()
		securityManager = new SecurityManager(DEFAULT_SECURITY_POLICY)
		securityMonitor = new SecurityMonitor(auditLogger, securityManager, DEFAULT_SECURITY_MONITOR_CONFIG)
	})

	afterEach(async () => {
		await securityMonitor.stop()
		await auditLogger.dispose()
	})

	describe("initialization", () => {
		it("should initialize with default configuration", () => {
			expect(securityMonitor.getConfig()).toEqual(DEFAULT_SECURITY_MONITOR_CONFIG)
		})

		it("should start and stop monitoring", async () => {
			await securityMonitor.start()
			expect(securityMonitor.getConfig().enabled).toBe(true)

			await securityMonitor.stop()
			// Should not throw
		})
	})

	describe("alert creation", () => {
		it("should create security alert", async () => {
			const alertData = {
				type: SecurityAlertType.THRESHOLD_EXCEEDED,
				severity: SecurityAlertSeverity.WARNING,
				title: "Test Alert",
				description: "Test alert description",
				details: { test: true },
				recommendations: ["Test recommendation"],
			}

			const alert = await securityMonitor.createAlert(alertData)

			expect(alert.id).toBeDefined()
			expect(alert.type).toBe(SecurityAlertType.THRESHOLD_EXCEEDED)
			expect(alert.severity).toBe(SecurityAlertSeverity.WARNING)
			expect(alert.title).toBe("Test Alert")
			expect(alert.acknowledged).toBe(false)
		})

		it("should update metrics when creating alerts", async () => {
			await securityMonitor.createAlert({
				type: SecurityAlertType.ANOMALY_DETECTED,
				severity: SecurityAlertSeverity.CRITICAL,
				title: "Critical Alert",
				description: "Critical alert description",
				details: {},
				recommendations: [],
			})

			const metrics = securityMonitor.getMetrics()
			expect(metrics.totalAlerts).toBe(1)
			expect(metrics.alertsByType[SecurityAlertType.ANOMALY_DETECTED]).toBe(1)
			expect(metrics.alertsBySeverity[SecurityAlertSeverity.CRITICAL]).toBe(1)
			expect(metrics.activeAlerts).toBe(1)
		})
	})

	describe("alert management", () => {
		let alertId: string

		beforeEach(async () => {
			const alert = await securityMonitor.createAlert({
				type: SecurityAlertType.SUSPICIOUS_PATTERN,
				severity: SecurityAlertSeverity.WARNING,
				title: "Test Alert",
				description: "Test description",
				details: {},
				recommendations: [],
			})
			alertId = alert.id
		})

		it("should acknowledge alerts", () => {
			const result = securityMonitor.acknowledgeAlert(alertId)
			expect(result).toBe(true)

			const activeAlerts = securityMonitor.getActiveAlerts()
			const alert = activeAlerts.find((a) => a.id === alertId)
			expect(alert?.acknowledged).toBe(true)
		})

		it("should resolve alerts", () => {
			const result = securityMonitor.resolveAlert(alertId)
			expect(result).toBe(true)

			const activeAlerts = securityMonitor.getActiveAlerts()
			const alert = activeAlerts.find((a) => a.id === alertId)
			expect(alert?.resolvedAt).toBeDefined()
		})

		it("should return false for non-existent alert operations", () => {
			expect(securityMonitor.acknowledgeAlert("non-existent")).toBe(false)
			expect(securityMonitor.resolveAlert("non-existent")).toBe(false)
		})
	})

	describe("configuration management", () => {
		it("should update configuration", () => {
			const newConfig = {
				alertThresholds: {
					violationsPerMinute: 10,
					violationsPerHour: 50,
					failureRateThreshold: 0.5,
					anomalyScoreThreshold: 0.9,
					suspiciousPatternThreshold: 0.8,
				},
			}

			securityMonitor.updateConfig(newConfig)
			const config = securityMonitor.getConfig()
			expect(config.alertThresholds.violationsPerMinute).toBe(10)
			expect(config.alertThresholds.failureRateThreshold).toBe(0.5)
		})
	})

	describe("metrics tracking", () => {
		it("should track alert metrics correctly", async () => {
			// Create multiple alerts
			await securityMonitor.createAlert({
				type: SecurityAlertType.ANOMALY_DETECTED,
				severity: SecurityAlertSeverity.CRITICAL,
				title: "Alert 1",
				description: "Description 1",
				details: {},
				recommendations: [],
			})

			await securityMonitor.createAlert({
				type: SecurityAlertType.THRESHOLD_EXCEEDED,
				severity: SecurityAlertSeverity.WARNING,
				title: "Alert 2",
				description: "Description 2",
				details: {},
				recommendations: [],
			})

			const metrics = securityMonitor.getMetrics()
			expect(metrics.totalAlerts).toBe(2)
			expect(metrics.alertsByType[SecurityAlertType.ANOMALY_DETECTED]).toBe(1)
			expect(metrics.alertsByType[SecurityAlertType.THRESHOLD_EXCEEDED]).toBe(1)
			expect(metrics.alertsBySeverity[SecurityAlertSeverity.CRITICAL]).toBe(1)
			expect(metrics.alertsBySeverity[SecurityAlertSeverity.WARNING]).toBe(1)
			expect(metrics.activeAlerts).toBe(2)
		})

		it("should update system health based on alerts", async () => {
			// Create critical alert
			await securityMonitor.createAlert({
				type: SecurityAlertType.SYSTEM_COMPROMISE,
				severity: SecurityAlertSeverity.CRITICAL,
				title: "System Compromise",
				description: "Critical system compromise detected",
				details: {},
				recommendations: [],
			})

			const metrics = securityMonitor.getMetrics()
			expect(metrics.systemHealth).toBe("critical")
		})
	})

	describe("alert validation", () => {
		it("should validate alert data", async () => {
			const invalidAlertData = {
				type: "invalid_type" as any,
				severity: SecurityAlertSeverity.WARNING,
				title: "Test Alert",
				description: "Test description",
				details: {},
				recommendations: [],
			}

			await expect(securityMonitor.createAlert(invalidAlertData)).rejects.toThrow()
		})

		it("should require all mandatory fields", async () => {
			const incompleteAlertData = {
				type: SecurityAlertType.ANOMALY_DETECTED,
				severity: SecurityAlertSeverity.WARNING,
				// Missing title and description
				details: {},
				recommendations: [],
			} as any

			await expect(securityMonitor.createAlert(incompleteAlertData)).rejects.toThrow()
		})
	})

	describe("active alerts", () => {
		it("should return only unresolved alerts", async () => {
			const alert1 = await securityMonitor.createAlert({
				type: SecurityAlertType.ANOMALY_DETECTED,
				severity: SecurityAlertSeverity.WARNING,
				title: "Active Alert",
				description: "This alert is active",
				details: {},
				recommendations: [],
			})

			const alert2 = await securityMonitor.createAlert({
				type: SecurityAlertType.THRESHOLD_EXCEEDED,
				severity: SecurityAlertSeverity.CRITICAL,
				title: "Resolved Alert",
				description: "This alert will be resolved",
				details: {},
				recommendations: [],
			})

			// Resolve one alert
			securityMonitor.resolveAlert(alert2.id)

			const activeAlerts = securityMonitor.getActiveAlerts()
			expect(activeAlerts).toHaveLength(1)
			expect(activeAlerts[0].id).toBe(alert1.id)
		})

		it("should sort alerts by timestamp (newest first)", async () => {
			const alert1 = await securityMonitor.createAlert({
				type: SecurityAlertType.ANOMALY_DETECTED,
				severity: SecurityAlertSeverity.WARNING,
				title: "First Alert",
				description: "First alert",
				details: {},
				recommendations: [],
			})

			// Wait a bit to ensure different timestamps
			await new Promise((resolve) => setTimeout(resolve, 10))

			const alert2 = await securityMonitor.createAlert({
				type: SecurityAlertType.THRESHOLD_EXCEEDED,
				severity: SecurityAlertSeverity.CRITICAL,
				title: "Second Alert",
				description: "Second alert",
				details: {},
				recommendations: [],
			})

			const activeAlerts = securityMonitor.getActiveAlerts()
			expect(activeAlerts).toHaveLength(2)
			expect(activeAlerts[0].id).toBe(alert2.id) // Newest first
			expect(activeAlerts[1].id).toBe(alert1.id)
		})
	})
})
