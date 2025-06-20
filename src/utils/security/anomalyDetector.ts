/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Anomaly detection and suspicious activity analysis for MCP security operations.
 * Provides machine learning-based pattern recognition and behavioral analysis.
 */

import { z } from "zod"
import { AuditEvent, AuditEventType, AuditSeverity } from "./auditLogger"
import { SecurityAlert, SecurityAlertType, SecurityAlertSeverity } from "./securityMonitor"

/**
 * Anomaly detection algorithms
 */
export enum AnomalyDetectionAlgorithm {
	STATISTICAL = "statistical",
	BEHAVIORAL = "behavioral",
	PATTERN_MATCHING = "pattern_matching",
	MACHINE_LEARNING = "machine_learning",
	HYBRID = "hybrid",
}

/**
 * Anomaly types
 */
export enum AnomalyType {
	FREQUENCY_ANOMALY = "frequency_anomaly",
	TEMPORAL_ANOMALY = "temporal_anomaly",
	BEHAVIORAL_ANOMALY = "behavioral_anomaly",
	PATTERN_ANOMALY = "pattern_anomaly",
	VOLUME_ANOMALY = "volume_anomaly",
	SEQUENCE_ANOMALY = "sequence_anomaly",
	OUTLIER_DETECTION = "outlier_detection",
}

/**
 * Anomaly detection result
 */
export interface AnomalyDetectionResult {
	id: string
	type: AnomalyType
	algorithm: AnomalyDetectionAlgorithm
	timestamp: number
	confidence: number
	severity: "low" | "medium" | "high" | "critical"
	description: string
	evidence: AnomalyEvidence[]
	affectedEntities: string[]
	riskScore: number
	recommendations: string[]
	falsePositiveProbability: number
}

/**
 * Anomaly evidence
 */
export interface AnomalyEvidence {
	type: "statistical" | "behavioral" | "pattern" | "temporal"
	description: string
	value: number
	threshold: number
	deviation: number
	context: Record<string, unknown>
}

/**
 * Behavioral baseline
 */
export interface BehavioralBaseline {
	entityId: string
	entityType: "server" | "tool" | "user" | "session"
	metrics: {
		averageFrequency: number
		standardDeviation: number
		typicalTimeWindows: number[]
		commonPatterns: string[]
		volumeBaseline: number
	}
	lastUpdated: number
	sampleSize: number
	confidence: number
}

/**
 * Anomaly detection configuration
 */
export interface AnomalyDetectorConfig {
	enabled: boolean
	algorithms: AnomalyDetectionAlgorithm[]
	sensitivityLevel: "low" | "medium" | "high"
	baselineWindow: number // milliseconds
	detectionWindow: number // milliseconds
	minimumSampleSize: number
	confidenceThreshold: number
	falsePositiveThreshold: number
	updateInterval: number
	retentionDays: number
}

/**
 * Statistical metrics for anomaly detection
 */
export interface StatisticalMetrics {
	mean: number
	median: number
	standardDeviation: number
	variance: number
	skewness: number
	kurtosis: number
	percentiles: Record<number, number>
	outliers: number[]
}

/**
 * Pattern signature for pattern matching
 */
export interface PatternSignature {
	id: string
	name: string
	pattern: string
	description: string
	severity: "low" | "medium" | "high" | "critical"
	confidence: number
	examples: string[]
	falsePositiveRate: number
}

/**
 * Zod schemas
 */
export const AnomalyDetectionAlgorithmSchema = z.nativeEnum(AnomalyDetectionAlgorithm)
export const AnomalyTypeSchema = z.nativeEnum(AnomalyType)

export const AnomalyEvidenceSchema = z.object({
	type: z.enum(["statistical", "behavioral", "pattern", "temporal"]),
	description: z.string(),
	value: z.number(),
	threshold: z.number(),
	deviation: z.number(),
	context: z.record(z.unknown()),
})

export const AnomalyDetectionResultSchema = z.object({
	id: z.string(),
	type: AnomalyTypeSchema,
	algorithm: AnomalyDetectionAlgorithmSchema,
	timestamp: z.number(),
	confidence: z.number().min(0).max(1),
	severity: z.enum(["low", "medium", "high", "critical"]),
	description: z.string(),
	evidence: z.array(AnomalyEvidenceSchema),
	affectedEntities: z.array(z.string()),
	riskScore: z.number().min(0).max(1),
	recommendations: z.array(z.string()),
	falsePositiveProbability: z.number().min(0).max(1),
})

export const BehavioralBaselineSchema = z.object({
	entityId: z.string(),
	entityType: z.enum(["server", "tool", "user", "session"]),
	metrics: z.object({
		averageFrequency: z.number(),
		standardDeviation: z.number(),
		typicalTimeWindows: z.array(z.number()),
		commonPatterns: z.array(z.string()),
		volumeBaseline: z.number(),
	}),
	lastUpdated: z.number(),
	sampleSize: z.number(),
	confidence: z.number().min(0).max(1),
})

export const AnomalyDetectorConfigSchema = z.object({
	enabled: z.boolean(),
	algorithms: z.array(AnomalyDetectionAlgorithmSchema),
	sensitivityLevel: z.enum(["low", "medium", "high"]),
	baselineWindow: z.number().positive(),
	detectionWindow: z.number().positive(),
	minimumSampleSize: z.number().positive(),
	confidenceThreshold: z.number().min(0).max(1),
	falsePositiveThreshold: z.number().min(0).max(1),
	updateInterval: z.number().positive(),
	retentionDays: z.number().positive(),
})

/**
 * Default anomaly detector configuration
 */
export const DEFAULT_ANOMALY_DETECTOR_CONFIG: AnomalyDetectorConfig = {
	enabled: true,
	algorithms: [
		AnomalyDetectionAlgorithm.STATISTICAL,
		AnomalyDetectionAlgorithm.BEHAVIORAL,
		AnomalyDetectionAlgorithm.PATTERN_MATCHING,
	],
	sensitivityLevel: "medium",
	baselineWindow: 7 * 24 * 60 * 60 * 1000, // 7 days
	detectionWindow: 60 * 60 * 1000, // 1 hour
	minimumSampleSize: 50,
	confidenceThreshold: 0.7,
	falsePositiveThreshold: 0.1,
	updateInterval: 60 * 60 * 1000, // 1 hour
	retentionDays: 30,
}

/**
 * Anomaly detector implementation
 */
export class AnomalyDetector {
	private config: AnomalyDetectorConfig
	private baselines: Map<string, BehavioralBaseline> = new Map()
	private patternSignatures: Map<string, PatternSignature> = new Map()
	private detectionResults: Map<string, AnomalyDetectionResult> = new Map()
	private updateTimer?: NodeJS.Timeout

	constructor(config: AnomalyDetectorConfig = DEFAULT_ANOMALY_DETECTOR_CONFIG) {
		this.config = config
		this.initializePatternSignatures()
	}

	/**
	 * Initialize known pattern signatures
	 */
	private initializePatternSignatures(): void {
		const signatures: PatternSignature[] = [
			{
				id: "brute_force_auth",
				name: "Brute Force Authentication",
				pattern: "repeated_auth_failures",
				description: "Multiple failed authentication attempts in short time",
				severity: "high",
				confidence: 0.9,
				examples: ["5+ failed logins in 1 minute", "10+ failed logins in 5 minutes"],
				falsePositiveRate: 0.05,
			},
			{
				id: "privilege_escalation",
				name: "Privilege Escalation",
				pattern: "rapid_role_elevation",
				description: "Rapid or unusual privilege escalation attempts",
				severity: "critical",
				confidence: 0.85,
				examples: ["Multiple role elevation requests", "Escalation to admin privileges"],
				falsePositiveRate: 0.02,
			},
			{
				id: "data_exfiltration",
				name: "Data Exfiltration",
				pattern: "high_volume_access",
				description: "Unusually high volume of data access",
				severity: "high",
				confidence: 0.8,
				examples: ["Large number of resource accesses", "Bulk data retrieval"],
				falsePositiveRate: 0.1,
			},
			{
				id: "lateral_movement",
				name: "Lateral Movement",
				pattern: "cross_server_activity",
				description: "Unusual cross-server activity patterns",
				severity: "medium",
				confidence: 0.75,
				examples: ["Access to multiple servers", "Tool usage across servers"],
				falsePositiveRate: 0.15,
			},
		]

		for (const signature of signatures) {
			this.patternSignatures.set(signature.id, signature)
		}
	}

	/**
	 * Start anomaly detection
	 */
	async start(): Promise<void> {
		if (!this.config.enabled) {
			return
		}

		this.updateTimer = setInterval(async () => {
			await this.updateBaselines()
		}, this.config.updateInterval)
	}

	/**
	 * Stop anomaly detection
	 */
	async stop(): Promise<void> {
		if (this.updateTimer) {
			clearInterval(this.updateTimer)
			this.updateTimer = undefined
		}
	}

	/**
	 * Analyze events for anomalies
	 */
	async analyzeEvents(events: AuditEvent[]): Promise<AnomalyDetectionResult[]> {
		const results: AnomalyDetectionResult[] = []

		if (!this.config.enabled || events.length === 0) {
			return results
		}

		// Run different detection algorithms
		for (const algorithm of this.config.algorithms) {
			const algorithmResults = await this.runDetectionAlgorithm(algorithm, events)
			results.push(...algorithmResults)
		}

		// Filter results by confidence threshold
		const filteredResults = results.filter(
			(result) =>
				result.confidence >= this.config.confidenceThreshold &&
				result.falsePositiveProbability <= this.config.falsePositiveThreshold,
		)

		// Store results
		for (const result of filteredResults) {
			this.detectionResults.set(result.id, result)
		}

		// Clean up old results
		this.cleanupOldResults()

		return filteredResults
	}

	/**
	 * Run specific detection algorithm
	 */
	private async runDetectionAlgorithm(
		algorithm: AnomalyDetectionAlgorithm,
		events: AuditEvent[],
	): Promise<AnomalyDetectionResult[]> {
		switch (algorithm) {
			case AnomalyDetectionAlgorithm.STATISTICAL:
				return this.runStatisticalDetection(events)
			case AnomalyDetectionAlgorithm.BEHAVIORAL:
				return this.runBehavioralDetection(events)
			case AnomalyDetectionAlgorithm.PATTERN_MATCHING:
				return this.runPatternMatching(events)
			case AnomalyDetectionAlgorithm.MACHINE_LEARNING:
				return this.runMLDetection(events)
			case AnomalyDetectionAlgorithm.HYBRID:
				return this.runHybridDetection(events)
			default:
				return []
		}
	}

	/**
	 * Statistical anomaly detection
	 */
	private async runStatisticalDetection(events: AuditEvent[]): Promise<AnomalyDetectionResult[]> {
		const results: AnomalyDetectionResult[] = []

		// Frequency analysis
		const frequencyAnomalies = this.detectFrequencyAnomalies(events)
		results.push(...frequencyAnomalies)

		// Volume analysis
		const volumeAnomalies = this.detectVolumeAnomalies(events)
		results.push(...volumeAnomalies)

		// Temporal analysis
		const temporalAnomalies = this.detectTemporalAnomalies(events)
		results.push(...temporalAnomalies)

		return results
	}

	/**
	 * Behavioral anomaly detection
	 */
	private async runBehavioralDetection(events: AuditEvent[]): Promise<AnomalyDetectionResult[]> {
		const results: AnomalyDetectionResult[] = []

		// Group events by entity
		const eventsByServer = this.groupEventsByServer(events)
		const eventsByTool = this.groupEventsByTool(events)

		// Analyze server behavior
		for (const [serverId, serverEvents] of eventsByServer.entries()) {
			const baseline = this.baselines.get(`server:${serverId}`)
			if (baseline) {
				const anomalies = this.detectBehavioralAnomalies(serverEvents, baseline)
				results.push(...anomalies)
			}
		}

		// Analyze tool behavior
		for (const [toolId, toolEvents] of eventsByTool.entries()) {
			const baseline = this.baselines.get(`tool:${toolId}`)
			if (baseline) {
				const anomalies = this.detectBehavioralAnomalies(toolEvents, baseline)
				results.push(...anomalies)
			}
		}

		return results
	}

	/**
	 * Pattern matching detection
	 */
	private async runPatternMatching(events: AuditEvent[]): Promise<AnomalyDetectionResult[]> {
		const results: AnomalyDetectionResult[] = []

		for (const [signatureId, signature] of this.patternSignatures.entries()) {
			const matches = this.matchPattern(events, signature)
			if (matches.length > 0) {
				const anomaly = this.createPatternAnomaly(signature, matches, events)
				if (anomaly) {
					results.push(anomaly)
				}
			}
		}

		return results
	}

	/**
	 * Machine learning detection (simplified implementation)
	 */
	private async runMLDetection(events: AuditEvent[]): Promise<AnomalyDetectionResult[]> {
		const results: AnomalyDetectionResult[] = []

		// Simplified ML approach using clustering and outlier detection
		const features = this.extractFeatures(events)
		const outliers = this.detectOutliers(features)

		for (const outlier of outliers) {
			const anomaly: AnomalyDetectionResult = {
				id: `ml_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
				type: AnomalyType.OUTLIER_DETECTION,
				algorithm: AnomalyDetectionAlgorithm.MACHINE_LEARNING,
				timestamp: Date.now(),
				confidence: outlier.confidence,
				severity: this.mapConfidenceToSeverity(outlier.confidence),
				description: `Machine learning detected outlier behavior`,
				evidence: [
					{
						type: "statistical",
						description: "Outlier detection score",
						value: outlier.score,
						threshold: outlier.threshold,
						deviation: outlier.deviation,
						context: outlier.context,
					},
				],
				affectedEntities: outlier.entities,
				riskScore: outlier.confidence,
				recommendations: [
					"Investigate the detected outlier behavior",
					"Review associated events for suspicious activity",
				],
				falsePositiveProbability: 0.1,
			}
			results.push(anomaly)
		}

		return results
	}

	/**
	 * Hybrid detection combining multiple algorithms
	 */
	private async runHybridDetection(events: AuditEvent[]): Promise<AnomalyDetectionResult[]> {
		const results: AnomalyDetectionResult[] = []

		// Run multiple algorithms and combine results
		const statisticalResults = await this.runStatisticalDetection(events)
		const behavioralResults = await this.runBehavioralDetection(events)
		const patternResults = await this.runPatternMatching(events)

		// Combine and correlate results
		const correlatedResults = this.correlateResults([
			...statisticalResults,
			...behavioralResults,
			...patternResults,
		])

		results.push(...correlatedResults)

		return results
	}

	/**
	 * Detect frequency anomalies
	 */
	private detectFrequencyAnomalies(events: AuditEvent[]): AnomalyDetectionResult[] {
		const results: AnomalyDetectionResult[] = []
		const timeWindows = this.createTimeWindows(events, 60 * 1000) // 1-minute windows

		for (const window of timeWindows) {
			const eventCount = window.events.length
			const statistics = this.calculateStatistics(timeWindows.map((w) => w.events.length))

			if (eventCount > statistics.mean + 2 * statistics.standardDeviation) {
				const anomaly: AnomalyDetectionResult = {
					id: `freq_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
					type: AnomalyType.FREQUENCY_ANOMALY,
					algorithm: AnomalyDetectionAlgorithm.STATISTICAL,
					timestamp: window.start,
					confidence: this.calculateConfidence(eventCount, statistics.mean, statistics.standardDeviation),
					severity: this.mapDeviationToSeverity(eventCount, statistics.mean, statistics.standardDeviation),
					description: `Unusual frequency of events detected: ${eventCount} events in 1 minute`,
					evidence: [
						{
							type: "statistical",
							description: "Event frequency deviation",
							value: eventCount,
							threshold: statistics.mean + 2 * statistics.standardDeviation,
							deviation: (eventCount - statistics.mean) / statistics.standardDeviation,
							context: { timeWindow: "1 minute", baseline: statistics.mean },
						},
					],
					affectedEntities: [...new Set(window.events.map((e) => e.serverName).filter(Boolean) as string[])],
					riskScore: Math.min((eventCount - statistics.mean) / statistics.mean, 1),
					recommendations: [
						"Investigate the cause of increased activity",
						"Check for potential DDoS or automated attacks",
					],
					falsePositiveProbability: 0.05,
				}
				results.push(anomaly)
			}
		}

		return results
	}

	/**
	 * Detect volume anomalies
	 */
	private detectVolumeAnomalies(events: AuditEvent[]): AnomalyDetectionResult[] {
		const results: AnomalyDetectionResult[] = []

		// Group by server and analyze volume
		const eventsByServer = this.groupEventsByServer(events)

		for (const [serverId, serverEvents] of eventsByServer.entries()) {
			const baseline = this.baselines.get(`server:${serverId}`)
			if (!baseline) continue

			const currentVolume = serverEvents.length
			const expectedVolume = baseline.metrics.volumeBaseline
			const deviation = Math.abs(currentVolume - expectedVolume) / baseline.metrics.standardDeviation

			if (deviation > 2) {
				const anomaly: AnomalyDetectionResult = {
					id: `vol_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
					type: AnomalyType.VOLUME_ANOMALY,
					algorithm: AnomalyDetectionAlgorithm.STATISTICAL,
					timestamp: Date.now(),
					confidence: Math.min(deviation / 3, 1),
					severity: this.mapDeviationToSeverity(
						currentVolume,
						expectedVolume,
						baseline.metrics.standardDeviation,
					),
					description: `Volume anomaly detected for server ${serverId}: ${currentVolume} vs expected ${expectedVolume}`,
					evidence: [
						{
							type: "statistical",
							description: "Volume deviation from baseline",
							value: currentVolume,
							threshold: expectedVolume + 2 * baseline.metrics.standardDeviation,
							deviation,
							context: { serverId, baseline: expectedVolume },
						},
					],
					affectedEntities: [serverId],
					riskScore: Math.min(deviation / 5, 1),
					recommendations: ["Investigate unusual activity volume", "Check for automated or bulk operations"],
					falsePositiveProbability: 0.08,
				}
				results.push(anomaly)
			}
		}

		return results
	}

	/**
	 * Detect temporal anomalies
	 */
	private detectTemporalAnomalies(events: AuditEvent[]): AnomalyDetectionResult[] {
		const results: AnomalyDetectionResult[] = []

		// Analyze activity by hour of day
		const hourlyActivity: Record<number, number> = {}
		for (const event of events) {
			const hour = new Date(event.timestamp).getHours()
			hourlyActivity[hour] = (hourlyActivity[hour] || 0) + 1
		}

		// Detect unusual activity in off-hours (22:00 - 06:00)
		const offHours = [22, 23, 0, 1, 2, 3, 4, 5, 6]
		const offHourActivity = offHours.reduce((sum, hour) => sum + (hourlyActivity[hour] || 0), 0)
		const totalActivity = Object.values(hourlyActivity).reduce((sum, count) => sum + count, 0)
		const offHourRatio = totalActivity > 0 ? offHourActivity / totalActivity : 0

		if (offHourRatio > 0.3) {
			// More than 30% activity in off-hours
			const anomaly: AnomalyDetectionResult = {
				id: `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
				type: AnomalyType.TEMPORAL_ANOMALY,
				algorithm: AnomalyDetectionAlgorithm.STATISTICAL,
				timestamp: Date.now(),
				confidence: Math.min(offHourRatio * 2, 1),
				severity: offHourRatio > 0.5 ? "high" : "medium",
				description: `Unusual off-hours activity detected: ${(offHourRatio * 100).toFixed(1)}% of activity`,
				evidence: [
					{
						type: "temporal",
						description: "Off-hours activity ratio",
						value: offHourRatio,
						threshold: 0.3,
						deviation: (offHourRatio - 0.1) / 0.1,
						context: { offHourActivity, totalActivity },
					},
				],
				affectedEntities: [...new Set(events.map((e) => e.serverName).filter(Boolean) as string[])],
				riskScore: offHourRatio,
				recommendations: [
					"Investigate off-hours activity",
					"Verify if activity is authorized",
					"Check for compromised accounts",
				],
				falsePositiveProbability: 0.1,
			}
			results.push(anomaly)
		}

		return results
	}

	/**
	 * Detect behavioral anomalies against baseline
	 */
	private detectBehavioralAnomalies(events: AuditEvent[], baseline: BehavioralBaseline): AnomalyDetectionResult[] {
		const results: AnomalyDetectionResult[] = []

		const currentFrequency = events.length / (this.config.detectionWindow / (60 * 60 * 1000)) // events per hour
		const expectedFrequency = baseline.metrics.averageFrequency
		const deviation = Math.abs(currentFrequency - expectedFrequency) / baseline.metrics.standardDeviation

		if (deviation > 2) {
			const anomaly: AnomalyDetectionResult = {
				id: `behav_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
				type: AnomalyType.BEHAVIORAL_ANOMALY,
				algorithm: AnomalyDetectionAlgorithm.BEHAVIORAL,
				timestamp: Date.now(),
				confidence: Math.min(deviation / 3, 1),
				severity: this.mapDeviationToSeverity(
					currentFrequency,
					expectedFrequency,
					baseline.metrics.standardDeviation,
				),
				description: `Behavioral anomaly detected for ${baseline.entityType} ${baseline.entityId}`,
				evidence: [
					{
						type: "behavioral",
						description: "Frequency deviation from baseline",
						value: currentFrequency,
						threshold: expectedFrequency + 2 * baseline.metrics.standardDeviation,
						deviation,
						context: { entityId: baseline.entityId, entityType: baseline.entityType },
					},
				],
				affectedEntities: [baseline.entityId],
				riskScore: Math.min(deviation / 5, 1),
				recommendations: [
					"Investigate behavioral change",
					"Verify if change is expected",
					"Update baseline if behavior is legitimate",
				],
				falsePositiveProbability: 0.06,
			}
			results.push(anomaly)
		}

		return results
	}

	/**
	 * Match events against pattern signatures
	 */
	private matchPattern(events: AuditEvent[], signature: PatternSignature): AuditEvent[] {
		const matches: AuditEvent[] = []

		switch (signature.pattern) {
			case "repeated_auth_failures":
				const authFailures = events.filter(
					(e) => e.type === AuditEventType.AUTHENTICATION_ATTEMPT && !e.success,
				)
				if (authFailures.length >= 5) {
					matches.push(...authFailures)
				}
				break

			case "rapid_role_elevation":
				const roleElevations = events.filter((e) => e.type === AuditEventType.ROLE_ELEVATION)
				if (roleElevations.length >= 3) {
					matches.push(...roleElevations)
				}
				break

			case "high_volume_access":
				const resourceAccess = events.filter((e) => e.type === AuditEventType.RESOURCE_ACCESS)
				if (resourceAccess.length >= 50) {
					matches.push(...resourceAccess)
				}
				break

			case "cross_server_activity":
				const servers = new Set(events.map((e) => e.serverName).filter(Boolean))
				if (servers.size >= 5) {
					matches.push(...events.filter((e) => e.serverName))
				}
				break
		}

		return matches
	}

	/**
	 * Create pattern anomaly from matches
	 */
	private createPatternAnomaly(
		signature: PatternSignature,
		matches: AuditEvent[],
		allEvents: AuditEvent[],
	): AnomalyDetectionResult | null {
		if (matches.length === 0) return null

		return {
			id: `pattern_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
			type: AnomalyType.PATTERN_ANOMALY,
			algorithm: AnomalyDetectionAlgorithm.PATTERN_MATCHING,
			timestamp: Date.now(),
			confidence: signature.confidence,
			severity: signature.severity,
			description: `Pattern detected: ${signature.name} - ${signature.description}`,
			evidence: [
				{
					type: "pattern",
					description: signature.description,
					value: matches.length,
					threshold: 1,
					deviation: matches.length - 1,
					context: { patternId: signature.id, examples: signature.examples },
				},
			],
			affectedEntities: [...new Set(matches.map((e) => e.serverName).filter(Boolean) as string[])],
			riskScore: signature.confidence,
			recommendations: [
				`Investigate ${signature.name.toLowerCase()}`,
				"Review security logs for related activity",
				"Consider implementing additional controls",
			],
			falsePositiveProbability: signature.falsePositiveRate,
		}
	}

	/**
	 * Update behavioral baselines
	 */
	private async updateBaselines(): Promise<void> {
		// This would typically analyze historical data to update baselines
		// For now, we'll implement a simplified version
		console.log("Updating behavioral baselines...")
	}

	/**
	 * Helper methods
	 */
	private groupEventsByServer(events: AuditEvent[]): Map<string, AuditEvent[]> {
		const groups = new Map<string, AuditEvent[]>()
		for (const event of events) {
			if (event.serverName) {
				const existing = groups.get(event.serverName) || []
				existing.push(event)
				groups.set(event.serverName, existing)
			}
		}
		return groups
	}

	private groupEventsByTool(events: AuditEvent[]): Map<string, AuditEvent[]> {
		const groups = new Map<string, AuditEvent[]>()
		for (const event of events) {
			if (event.toolName) {
				const existing = groups.get(event.toolName) || []
				existing.push(event)
				groups.set(event.toolName, existing)
			}
		}
		return groups
	}

	private createTimeWindows(
		events: AuditEvent[],
		windowSize: number,
	): Array<{ start: number; end: number; events: AuditEvent[] }> {
		if (events.length === 0) return []

		const sortedEvents = events.sort((a, b) => a.timestamp - b.timestamp)
		const windows: Array<{ start: number; end: number; events: AuditEvent[] }> = []

		const startTime = sortedEvents[0].timestamp
		const endTime = sortedEvents[sortedEvents.length - 1].timestamp

		for (let time = startTime; time <= endTime; time += windowSize) {
			const windowEvents = sortedEvents.filter((e) => e.timestamp >= time && e.timestamp < time + windowSize)
			windows.push({
				start: time,
				end: time + windowSize,
				events: windowEvents,
			})
		}

		return windows
	}

	private calculateStatistics(values: number[]): StatisticalMetrics {
		if (values.length === 0) {
			return {
				mean: 0,
				median: 0,
				standardDeviation: 0,
				variance: 0,
				skewness: 0,
				kurtosis: 0,
				percentiles: {},
				outliers: [],
			}
		}

		const sorted = values.slice().sort((a, b) => a - b)
		const mean = values.reduce((sum, val) => sum + val, 0) / values.length
		const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length
		const standardDeviation = Math.sqrt(variance)

		return {
			mean,
			median: sorted[Math.floor(sorted.length / 2)],
			standardDeviation,
			variance,
			skewness: 0, // Simplified
			kurtosis: 0, // Simplified
			percentiles: {
				25: sorted[Math.floor(sorted.length * 0.25)],
				50: sorted[Math.floor(sorted.length * 0.5)],
				75: sorted[Math.floor(sorted.length * 0.75)],
				90: sorted[Math.floor(sorted.length * 0.9)],
				95: sorted[Math.floor(sorted.length * 0.95)],
			},
			outliers: values.filter((val) => Math.abs(val - mean) > 2 * standardDeviation),
		}
	}

	private calculateConfidence(value: number, mean: number, standardDeviation: number): number {
		if (standardDeviation === 0) return 0
		const zScore = Math.abs(value - mean) / standardDeviation
		return Math.min(zScore / 3, 1) // Normalize to 0-1 range
	}

	private mapDeviationToSeverity(
		value: number,
		mean: number,
		standardDeviation: number,
	): "low" | "medium" | "high" | "critical" {
		if (standardDeviation === 0) return "low"
		const zScore = Math.abs(value - mean) / standardDeviation

		if (zScore >= 4) return "critical"
		if (zScore >= 3) return "high"
		if (zScore >= 2) return "medium"
		return "low"
	}

	private mapConfidenceToSeverity(confidence: number): "low" | "medium" | "high" | "critical" {
		if (confidence >= 0.9) return "critical"
		if (confidence >= 0.7) return "high"
		if (confidence >= 0.5) return "medium"
		return "low"
	}

	private extractFeatures(
		events: AuditEvent[],
	): Array<{ entities: string[]; score: number; context: Record<string, unknown> }> {
		// Simplified feature extraction for ML detection
		const features: Array<{ entities: string[]; score: number; context: Record<string, unknown> }> = []

		// Group events by server and calculate feature scores
		const eventsByServer = this.groupEventsByServer(events)

		for (const [serverId, serverEvents] of eventsByServer.entries()) {
			const eventTypes = new Set(serverEvents.map((e) => e.type))
			const timeSpan =
				serverEvents.length > 1
					? Math.max(...serverEvents.map((e) => e.timestamp)) -
						Math.min(...serverEvents.map((e) => e.timestamp))
					: 0

			// Calculate feature score based on diversity and frequency
			const diversityScore = eventTypes.size / Object.values(AuditEventType).length
			const frequencyScore = serverEvents.length / 100 // Normalize
			const timeScore = timeSpan > 0 ? Math.min(timeSpan / (60 * 60 * 1000), 1) : 0 // Hours

			const score = (diversityScore + frequencyScore + timeScore) / 3

			features.push({
				entities: [serverId],
				score,
				context: {
					serverId,
					eventCount: serverEvents.length,
					eventTypes: Array.from(eventTypes),
					timeSpan,
				},
			})
		}

		return features
	}

	private detectOutliers(
		features: Array<{ entities: string[]; score: number; context: Record<string, unknown> }>,
	): Array<{
		entities: string[]
		score: number
		threshold: number
		deviation: number
		confidence: number
		context: Record<string, unknown>
	}> {
		if (features.length === 0) return []

		const scores = features.map((f) => f.score)
		const statistics = this.calculateStatistics(scores)
		const threshold = statistics.mean + 2 * statistics.standardDeviation

		return features
			.filter((f) => f.score > threshold)
			.map((f) => ({
				entities: f.entities,
				score: f.score,
				threshold,
				deviation: (f.score - statistics.mean) / statistics.standardDeviation,
				confidence: Math.min((f.score - statistics.mean) / statistics.mean, 1),
				context: f.context,
			}))
	}

	private correlateResults(results: AnomalyDetectionResult[]): AnomalyDetectionResult[] {
		// Simplified correlation - group by affected entities and time proximity
		const correlatedResults: AnomalyDetectionResult[] = []
		const processed = new Set<string>()

		for (const result of results) {
			if (processed.has(result.id)) continue

			// Find related results
			const related = results.filter(
				(r) =>
					r.id !== result.id &&
					!processed.has(r.id) &&
					Math.abs(r.timestamp - result.timestamp) < 300000 && // 5 minutes
					r.affectedEntities.some((entity) => result.affectedEntities.includes(entity)),
			)

			if (related.length > 0) {
				// Create correlated result
				const correlatedResult: AnomalyDetectionResult = {
					...result,
					id: `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
					algorithm: AnomalyDetectionAlgorithm.HYBRID,
					confidence: Math.min(
						((result.confidence + related.reduce((sum, r) => sum + r.confidence, 0)) /
							(related.length + 1)) *
							1.2,
						1,
					),
					description: `Correlated anomaly: ${result.description} (${related.length} related anomalies)`,
					evidence: [...result.evidence, ...related.flatMap((r) => r.evidence)],
					affectedEntities: [
						...new Set([...result.affectedEntities, ...related.flatMap((r) => r.affectedEntities)]),
					],
					recommendations: [
						...result.recommendations,
						"Investigate correlated anomalies together",
						"Look for common root cause",
					],
				}

				correlatedResults.push(correlatedResult)
				processed.add(result.id)
				related.forEach((r) => processed.add(r.id))
			} else {
				correlatedResults.push(result)
				processed.add(result.id)
			}
		}

		return correlatedResults
	}

	private cleanupOldResults(): void {
		const cutoffTime = Date.now() - this.config.retentionDays * 24 * 60 * 60 * 1000

		for (const [id, result] of this.detectionResults.entries()) {
			if (result.timestamp < cutoffTime) {
				this.detectionResults.delete(id)
			}
		}
	}

	/**
	 * Get detection results
	 */
	getDetectionResults(): AnomalyDetectionResult[] {
		return Array.from(this.detectionResults.values()).sort((a, b) => b.timestamp - a.timestamp)
	}

	/**
	 * Get behavioral baselines
	 */
	getBaselines(): BehavioralBaseline[] {
		return Array.from(this.baselines.values())
	}

	/**
	 * Update configuration
	 */
	updateConfig(newConfig: Partial<AnomalyDetectorConfig>): void {
		this.config = { ...this.config, ...newConfig }
	}

	/**
	 * Get current configuration
	 */
	getConfig(): AnomalyDetectorConfig {
		return { ...this.config }
	}
}
