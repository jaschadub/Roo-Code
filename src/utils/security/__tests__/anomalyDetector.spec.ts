/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Test suite for AnomalyDetector - suspicious activity detection and analysis.
 */

import {
	AnomalyDetector,
	AnomalyDetectionAlgorithm,
	AnomalyType,
	DEFAULT_ANOMALY_DETECTOR_CONFIG,
} from "../anomalyDetector"
import { AuditEvent, AuditEventType, AuditSeverity } from "../auditLogger"

describe("AnomalyDetector", () => {
	let anomalyDetector: AnomalyDetector

	beforeEach(async () => {
		anomalyDetector = new AnomalyDetector(DEFAULT_ANOMALY_DETECTOR_CONFIG)
		await anomalyDetector.start()
	})

	afterEach(async () => {
		await anomalyDetector.stop()
	})

	describe("initialization", () => {
		it("should initialize with default configuration", () => {
			expect(anomalyDetector.getConfig()).toEqual(DEFAULT_ANOMALY_DETECTOR_CONFIG)
		})

		it("should start and stop detection", async () => {
			await anomalyDetector.start()
			expect(anomalyDetector.getConfig().enabled).toBe(true)

			await anomalyDetector.stop()
			// Should not throw
		})
	})

	describe("event analysis", () => {
		it("should analyze empty event list", async () => {
			const results = await anomalyDetector.analyzeEvents([])
			expect(results).toEqual([])
		})

		it("should analyze normal events without anomalies", async () => {
			const events: AuditEvent[] = [
				createMockEvent(AuditEventType.TOOL_EXECUTION, "server1", "tool1"),
				createMockEvent(AuditEventType.RESOURCE_ACCESS, "server1", "tool2"),
				createMockEvent(AuditEventType.PERMISSION_GRANTED, "server2", "tool1"),
			]

			const results = await anomalyDetector.analyzeEvents(events)
			expect(Array.isArray(results)).toBe(true)
		})

		it("should detect frequency anomalies", async () => {
			// Create many events in a short time window to trigger frequency anomaly
			const events: AuditEvent[] = []
			const baseTime = Date.now()

			for (let i = 0; i < 100; i++) {
				events.push(
					createMockEvent(
						AuditEventType.TOOL_EXECUTION,
						"server1",
						"tool1",
						baseTime + i * 1000, // 1 second apart
					),
				)
			}

			const results = await anomalyDetector.analyzeEvents(events)
			const frequencyAnomalies = results.filter((r) => r.type === AnomalyType.FREQUENCY_ANOMALY)
			expect(frequencyAnomalies.length).toBeGreaterThan(0)
		})

		it("should detect temporal anomalies", async () => {
			// Create events during off-hours (2 AM)
			const events: AuditEvent[] = []
			const offHourTime = new Date()
			offHourTime.setHours(2, 0, 0, 0) // 2 AM

			for (let i = 0; i < 20; i++) {
				events.push(
					createMockEvent(
						AuditEventType.TOOL_EXECUTION,
						"server1",
						"tool1",
						offHourTime.getTime() + i * 60000, // 1 minute apart
					),
				)
			}

			const results = await anomalyDetector.analyzeEvents(events)
			const temporalAnomalies = results.filter((r) => r.type === AnomalyType.TEMPORAL_ANOMALY)
			expect(temporalAnomalies.length).toBeGreaterThan(0)
		})

		it("should detect pattern anomalies", async () => {
			// Create pattern for repeated authentication failures
			const events: AuditEvent[] = []
			const baseTime = Date.now()

			for (let i = 0; i < 10; i++) {
				events.push({
					id: `auth_fail_${i}`,
					timestamp: baseTime + i * 1000,
					type: AuditEventType.AUTHENTICATION_ATTEMPT,
					severity: AuditSeverity.MEDIUM,
					serverName: "auth_server",
					success: false, // Failed authentication
					message: `Authentication failed for attempt ${i}`,
				})
			}

			const results = await anomalyDetector.analyzeEvents(events)
			const patternAnomalies = results.filter((r) => r.type === AnomalyType.PATTERN_ANOMALY)
			expect(patternAnomalies.length).toBeGreaterThan(0)
		})
	})

	describe("algorithm selection", () => {
		it("should run statistical detection", async () => {
			const config = {
				...DEFAULT_ANOMALY_DETECTOR_CONFIG,
				algorithms: [AnomalyDetectionAlgorithm.STATISTICAL],
			}
			const detector = new AnomalyDetector(config)
			await detector.start()

			const events = createMockEvents(50)
			const results = await detector.analyzeEvents(events)

			expect(Array.isArray(results)).toBe(true)
			await detector.stop()
		})

		it("should run behavioral detection", async () => {
			const config = {
				...DEFAULT_ANOMALY_DETECTOR_CONFIG,
				algorithms: [AnomalyDetectionAlgorithm.BEHAVIORAL],
			}
			const detector = new AnomalyDetector(config)
			await detector.start()

			const events = createMockEvents(50)
			const results = await detector.analyzeEvents(events)

			expect(Array.isArray(results)).toBe(true)
			await detector.stop()
		})

		it("should run pattern matching detection", async () => {
			const config = {
				...DEFAULT_ANOMALY_DETECTOR_CONFIG,
				algorithms: [AnomalyDetectionAlgorithm.PATTERN_MATCHING],
			}
			const detector = new AnomalyDetector(config)
			await detector.start()

			const events = createMockEvents(50)
			const results = await detector.analyzeEvents(events)

			expect(Array.isArray(results)).toBe(true)
			await detector.stop()
		})

		it("should run machine learning detection", async () => {
			const config = {
				...DEFAULT_ANOMALY_DETECTOR_CONFIG,
				algorithms: [AnomalyDetectionAlgorithm.MACHINE_LEARNING],
			}
			const detector = new AnomalyDetector(config)
			await detector.start()

			const events = createMockEvents(50)
			const results = await detector.analyzeEvents(events)

			expect(Array.isArray(results)).toBe(true)
			await detector.stop()
		})

		it("should run hybrid detection", async () => {
			const config = {
				...DEFAULT_ANOMALY_DETECTOR_CONFIG,
				algorithms: [AnomalyDetectionAlgorithm.HYBRID],
			}
			const detector = new AnomalyDetector(config)
			await detector.start()

			const events = createMockEvents(50)
			const results = await detector.analyzeEvents(events)

			expect(Array.isArray(results)).toBe(true)
			await detector.stop()
		})
	})

	describe("confidence filtering", () => {
		it("should filter results by confidence threshold", async () => {
			const config = {
				...DEFAULT_ANOMALY_DETECTOR_CONFIG,
				confidenceThreshold: 0.9, // Very high threshold
			}
			const detector = new AnomalyDetector(config)
			await detector.start()

			const events = createMockEvents(20)
			const results = await detector.analyzeEvents(events)

			// With high threshold, should have fewer results
			results.forEach((result) => {
				expect(result.confidence).toBeGreaterThanOrEqual(0.9)
			})

			await detector.stop()
		})

		it("should filter results by false positive threshold", async () => {
			const config = {
				...DEFAULT_ANOMALY_DETECTOR_CONFIG,
				falsePositiveThreshold: 0.05, // Very low threshold
			}
			const detector = new AnomalyDetector(config)
			await detector.start()

			const events = createMockEvents(20)
			const results = await detector.analyzeEvents(events)

			results.forEach((result) => {
				expect(result.falsePositiveProbability).toBeLessThanOrEqual(0.05)
			})

			await detector.stop()
		})
	})

	describe("configuration management", () => {
		it("should update configuration", () => {
			const newConfig = {
				sensitivityLevel: "high" as const,
				confidenceThreshold: 0.8,
			}

			anomalyDetector.updateConfig(newConfig)
			const config = anomalyDetector.getConfig()
			expect(config.sensitivityLevel).toBe("high")
			expect(config.confidenceThreshold).toBe(0.8)
		})

		it("should get current configuration", () => {
			const config = anomalyDetector.getConfig()
			expect(config).toEqual(DEFAULT_ANOMALY_DETECTOR_CONFIG)
		})
	})

	describe("detection results", () => {
		it("should store and retrieve detection results", async () => {
			const events = createMockEvents(10)
			const results = await anomalyDetector.analyzeEvents(events)

			const storedResults = anomalyDetector.getDetectionResults()
			expect(storedResults.length).toBe(results.length)
		})

		it("should sort results by timestamp", async () => {
			const events = createMockEvents(10)
			await anomalyDetector.analyzeEvents(events)

			const results = anomalyDetector.getDetectionResults()
			if (results.length > 1) {
				for (let i = 1; i < results.length; i++) {
					expect(results[i - 1].timestamp).toBeGreaterThanOrEqual(results[i].timestamp)
				}
			}
		})
	})

	describe("behavioral baselines", () => {
		it("should retrieve behavioral baselines", () => {
			const baselines = anomalyDetector.getBaselines()
			expect(Array.isArray(baselines)).toBe(true)
		})
	})

	describe("disabled detection", () => {
		it("should not analyze events when disabled", async () => {
			const config = {
				...DEFAULT_ANOMALY_DETECTOR_CONFIG,
				enabled: false,
			}
			const detector = new AnomalyDetector(config)
			await detector.start()

			const events = createMockEvents(50)
			const results = await detector.analyzeEvents(events)

			expect(results).toEqual([])
			await detector.stop()
		})
	})
})

// Helper functions
function createMockEvent(type: AuditEventType, serverName: string, toolName?: string, timestamp?: number): AuditEvent {
	return {
		id: `event_${Math.random().toString(36).substr(2, 9)}`,
		timestamp: timestamp || Date.now(),
		type,
		severity: AuditSeverity.LOW,
		serverName,
		toolName,
		success: true,
		message: `Mock ${type} event`,
	}
}

function createMockEvents(count: number): AuditEvent[] {
	const events: AuditEvent[] = []
	const baseTime = Date.now()
	const eventTypes = Object.values(AuditEventType)
	const servers = ["server1", "server2", "server3"]
	const tools = ["tool1", "tool2", "tool3"]

	for (let i = 0; i < count; i++) {
		events.push({
			id: `event_${i}`,
			timestamp: baseTime + i * 1000,
			type: eventTypes[i % eventTypes.length],
			severity: AuditSeverity.LOW,
			serverName: servers[i % servers.length],
			toolName: tools[i % tools.length],
			success: Math.random() > 0.1, // 90% success rate
			message: `Mock event ${i}`,
		})
	}

	return events
}
