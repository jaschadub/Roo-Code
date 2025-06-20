/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Core permission validation and management system for MCP tools.
 * Replaces the weak binary `alwaysAllow` system with granular, time-limited permissions.
 */

import { z } from "zod"

/**
 * Permission scopes define what level of access is granted
 */
export enum PermissionScope {
	READ_ONLY = "read_only",
	EXECUTE = "execute",
	ADMIN = "admin",
	FULL_ACCESS = "full_access",
}

/**
 * Permission types for different resource categories
 */
export enum PermissionType {
	TOOL_EXECUTION = "tool_execution",
	RESOURCE_ACCESS = "resource_access",
	FILE_SYSTEM = "file_system",
	NETWORK = "network",
	COMMAND_EXECUTION = "command_execution",
}

/**
 * Conditional permission triggers
 */
export enum PermissionCondition {
	TIME_BASED = "time_based",
	CONTEXT_BASED = "context_based",
	USER_PRESENCE = "user_presence",
	WORKSPACE_BASED = "workspace_based",
}

/**
 * Permission status tracking
 */
export enum PermissionStatus {
	ACTIVE = "active",
	EXPIRED = "expired",
	REVOKED = "revoked",
	PENDING = "pending",
	DENIED = "denied",
}

/**
 * Resource-specific permission constraints
 */
export interface ResourceConstraints {
	allowedPaths?: string[]
	blockedPaths?: string[]
	allowedDomains?: string[]
	blockedDomains?: string[]
	maxFileSize?: number
	allowedMimeTypes?: string[]
}

/**
 * Usage quota limits
 */
export interface UsageQuota {
	maxExecutions?: number
	maxExecutionsPerHour?: number
	maxExecutionsPerDay?: number
	rateLimitPerMinute?: number
	maxConcurrentExecutions?: number
}

/**
 * Time-based permission constraints
 */
export interface TimeConstraints {
	expiresAt?: number
	validFrom?: number
	validUntil?: number
	allowedHours?: number[] // 0-23
	allowedDays?: number[] // 0-6 (Sunday-Saturday)
	timezone?: string
}

/**
 * Conditional permission rules
 */
export interface ConditionalRules {
	condition: PermissionCondition
	parameters: Record<string, unknown>
	description?: string
}

/**
 * Core permission object with granular controls
 */
export interface Permission {
	id: string
	serverName: string
	toolName?: string
	resourcePattern?: string
	type: PermissionType
	scope: PermissionScope
	status: PermissionStatus

	// Time-based controls
	grantedAt: number
	expiresAt?: number
	lastUsedAt?: number

	// Usage tracking
	usageCount: number
	quota?: UsageQuota

	// Resource constraints
	resourceConstraints?: ResourceConstraints

	// Time constraints
	timeConstraints?: TimeConstraints

	// Conditional rules
	conditionalRules?: ConditionalRules[]

	// Delegation
	delegatedBy?: string
	delegatedTo?: string
	canDelegate?: boolean

	// Metadata
	reason?: string
	userApproved: boolean
	autoGranted: boolean
	riskLevel: "low" | "medium" | "high"

	// Audit trail
	auditTrail: PermissionAuditEntry[]
}

/**
 * Permission audit entry for tracking usage and changes
 */
export interface PermissionAuditEntry {
	timestamp: number
	action: "granted" | "used" | "denied" | "expired" | "revoked" | "renewed" | "delegated"
	details?: string
	userAgent?: string
	ipAddress?: string
	context?: Record<string, unknown>
}

/**
 * Permission request for user approval
 */
export interface PermissionRequest {
	id: string
	serverName: string
	toolName?: string
	resourcePattern?: string
	type: PermissionType
	requestedScope: PermissionScope
	reason: string
	requestedDuration?: number
	requestedQuota?: UsageQuota
	resourceConstraints?: ResourceConstraints
	riskAssessment: {
		level: "low" | "medium" | "high"
		factors: string[]
		recommendations: string[]
	}
	requestedAt: number
	expiresAt?: number
}

/**
 * Permission validation result
 */
export interface PermissionValidationResult {
	allowed: boolean
	permission?: Permission
	reason: string
	violations?: string[]
	suggestedActions?: string[]
	requiresApproval?: boolean
	riskLevel: "low" | "medium" | "high"
}

/**
 * Permission policy configuration
 */
export interface PermissionPolicy {
	defaultScope: PermissionScope
	defaultDuration: number // milliseconds
	maxDuration: number
	requireApprovalFor: PermissionType[]
	autoGrantFor: PermissionType[]
	defaultQuota: UsageQuota
	riskThresholds: {
		low: number
		medium: number
		high: number
	}
	allowDelegation: boolean
	maxDelegationDepth: number
}

/**
 * Zod schemas for validation
 */
export const PermissionScopeSchema = z.nativeEnum(PermissionScope)
export const PermissionTypeSchema = z.nativeEnum(PermissionType)
export const PermissionStatusSchema = z.nativeEnum(PermissionStatus)
export const PermissionConditionSchema = z.nativeEnum(PermissionCondition)

export const ResourceConstraintsSchema = z.object({
	allowedPaths: z.array(z.string()).optional(),
	blockedPaths: z.array(z.string()).optional(),
	allowedDomains: z.array(z.string()).optional(),
	blockedDomains: z.array(z.string()).optional(),
	maxFileSize: z.number().positive().optional(),
	allowedMimeTypes: z.array(z.string()).optional(),
})

export const UsageQuotaSchema = z.object({
	maxExecutions: z.number().positive().optional(),
	maxExecutionsPerHour: z.number().positive().optional(),
	maxExecutionsPerDay: z.number().positive().optional(),
	rateLimitPerMinute: z.number().positive().optional(),
	maxConcurrentExecutions: z.number().positive().optional(),
})

export const TimeConstraintsSchema = z.object({
	expiresAt: z.number().optional(),
	validFrom: z.number().optional(),
	validUntil: z.number().optional(),
	allowedHours: z.array(z.number().min(0).max(23)).optional(),
	allowedDays: z.array(z.number().min(0).max(6)).optional(),
	timezone: z.string().optional(),
})

export const ConditionalRulesSchema = z.object({
	condition: PermissionConditionSchema,
	parameters: z.record(z.unknown()),
	description: z.string().optional(),
})

export const PermissionAuditEntrySchema = z.object({
	timestamp: z.number(),
	action: z.enum(["granted", "used", "denied", "expired", "revoked", "renewed", "delegated"]),
	details: z.string().optional(),
	userAgent: z.string().optional(),
	ipAddress: z.string().optional(),
	context: z.record(z.unknown()).optional(),
})

export const PermissionSchema = z.object({
	id: z.string(),
	serverName: z.string(),
	toolName: z.string().optional(),
	resourcePattern: z.string().optional(),
	type: PermissionTypeSchema,
	scope: PermissionScopeSchema,
	status: PermissionStatusSchema,
	grantedAt: z.number(),
	expiresAt: z.number().optional(),
	lastUsedAt: z.number().optional(),
	usageCount: z.number().default(0),
	quota: UsageQuotaSchema.optional(),
	resourceConstraints: ResourceConstraintsSchema.optional(),
	timeConstraints: TimeConstraintsSchema.optional(),
	conditionalRules: z.array(ConditionalRulesSchema).optional(),
	delegatedBy: z.string().optional(),
	delegatedTo: z.string().optional(),
	canDelegate: z.boolean().default(false),
	reason: z.string().optional(),
	userApproved: z.boolean(),
	autoGranted: z.boolean(),
	riskLevel: z.enum(["low", "medium", "high"]),
	auditTrail: z.array(PermissionAuditEntrySchema),
})

export const PermissionRequestSchema = z.object({
	id: z.string(),
	serverName: z.string(),
	toolName: z.string().optional(),
	resourcePattern: z.string().optional(),
	type: PermissionTypeSchema,
	requestedScope: PermissionScopeSchema,
	reason: z.string(),
	requestedDuration: z.number().optional(),
	requestedQuota: UsageQuotaSchema.optional(),
	resourceConstraints: ResourceConstraintsSchema.optional(),
	riskAssessment: z.object({
		level: z.enum(["low", "medium", "high"]),
		factors: z.array(z.string()),
		recommendations: z.array(z.string()),
	}),
	requestedAt: z.number(),
	expiresAt: z.number().optional(),
})

export const PermissionPolicySchema = z.object({
	defaultScope: PermissionScopeSchema,
	defaultDuration: z.number().positive(),
	maxDuration: z.number().positive(),
	requireApprovalFor: z.array(PermissionTypeSchema),
	autoGrantFor: z.array(PermissionTypeSchema),
	defaultQuota: UsageQuotaSchema,
	riskThresholds: z.object({
		low: z.number(),
		medium: z.number(),
		high: z.number(),
	}),
	allowDelegation: z.boolean(),
	maxDelegationDepth: z.number().positive(),
})

/**
 * Default permission policy
 */
export const DEFAULT_PERMISSION_POLICY: PermissionPolicy = {
	defaultScope: PermissionScope.READ_ONLY,
	defaultDuration: 24 * 60 * 60 * 1000, // 24 hours
	maxDuration: 7 * 24 * 60 * 60 * 1000, // 7 days
	requireApprovalFor: [PermissionType.COMMAND_EXECUTION, PermissionType.FILE_SYSTEM, PermissionType.NETWORK],
	autoGrantFor: [PermissionType.RESOURCE_ACCESS],
	defaultQuota: {
		maxExecutions: 100,
		maxExecutionsPerHour: 10,
		rateLimitPerMinute: 5,
		maxConcurrentExecutions: 3,
	},
	riskThresholds: {
		low: 0.3,
		medium: 0.6,
		high: 0.8,
	},
	allowDelegation: false,
	maxDelegationDepth: 2,
}

/**
 * Core permission manager class
 */
export class PermissionManager {
	private permissions: Map<string, Permission> = new Map()
	private pendingRequests: Map<string, PermissionRequest> = new Map()
	private policy: PermissionPolicy

	constructor(policy: PermissionPolicy = DEFAULT_PERMISSION_POLICY) {
		this.policy = policy
	}

	/**
	 * Generate a unique permission ID
	 */
	private generatePermissionId(): string {
		return `perm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
	}

	/**
	 * Assess risk level for a permission request
	 */
	private assessRisk(request: PermissionRequest): { level: "low" | "medium" | "high"; factors: string[] } {
		const factors: string[] = []
		let riskScore = 0

		// Type-based risk
		switch (request.type) {
			case PermissionType.COMMAND_EXECUTION:
				riskScore += 0.4
				factors.push("Command execution access")
				break
			case PermissionType.FILE_SYSTEM:
				riskScore += 0.3
				factors.push("File system access")
				break
			case PermissionType.NETWORK:
				riskScore += 0.3
				factors.push("Network access")
				break
			case PermissionType.TOOL_EXECUTION:
				riskScore += 0.2
				factors.push("Tool execution")
				break
			case PermissionType.RESOURCE_ACCESS:
				riskScore += 0.1
				factors.push("Resource access")
				break
		}

		// Scope-based risk
		switch (request.requestedScope) {
			case PermissionScope.FULL_ACCESS:
				riskScore += 0.3
				factors.push("Full access scope")
				break
			case PermissionScope.ADMIN:
				riskScore += 0.2
				factors.push("Admin scope")
				break
			case PermissionScope.EXECUTE:
				riskScore += 0.1
				factors.push("Execute scope")
				break
		}

		// Duration-based risk
		if (request.requestedDuration && request.requestedDuration > this.policy.defaultDuration) {
			riskScore += 0.1
			factors.push("Extended duration requested")
		}

		// Quota-based risk
		if (
			request.requestedQuota?.maxExecutions &&
			request.requestedQuota.maxExecutions > this.policy.defaultQuota.maxExecutions!
		) {
			riskScore += 0.1
			factors.push("High execution quota requested")
		}

		// Determine risk level
		let level: "low" | "medium" | "high"
		if (riskScore >= this.policy.riskThresholds.high) {
			level = "high"
		} else if (riskScore >= this.policy.riskThresholds.medium) {
			level = "medium"
		} else {
			level = "low"
		}

		return { level, factors }
	}

	/**
	 * Create a permission request
	 */
	createPermissionRequest(
		serverName: string,
		toolName: string | undefined,
		resourcePattern: string | undefined,
		type: PermissionType,
		requestedScope: PermissionScope = this.policy.defaultScope,
		reason: string,
		options: {
			duration?: number
			quota?: UsageQuota
			resourceConstraints?: ResourceConstraints
		} = {},
	): PermissionRequest {
		const id = this.generatePermissionId()
		const riskAssessment = this.assessRisk({
			id,
			serverName,
			toolName,
			resourcePattern,
			type,
			requestedScope,
			reason,
			requestedDuration: options.duration,
			requestedQuota: options.quota,
			resourceConstraints: options.resourceConstraints,
			requestedAt: Date.now(),
		} as PermissionRequest)

		const request: PermissionRequest = {
			id,
			serverName,
			toolName,
			resourcePattern,
			type,
			requestedScope,
			reason,
			requestedDuration: options.duration || this.policy.defaultDuration,
			requestedQuota: options.quota || this.policy.defaultQuota,
			resourceConstraints: options.resourceConstraints,
			riskAssessment: {
				level: riskAssessment.level,
				factors: riskAssessment.factors,
				recommendations: this.generateRecommendations(riskAssessment.level, riskAssessment.factors),
			},
			requestedAt: Date.now(),
			expiresAt: Date.now() + 24 * 60 * 60 * 1000, // Request expires in 24 hours
		}

		this.pendingRequests.set(id, request)
		return request
	}

	/**
	 * Generate security recommendations based on risk assessment
	 */
	private generateRecommendations(level: "low" | "medium" | "high", factors: string[]): string[] {
		const recommendations: string[] = []

		if (level === "high") {
			recommendations.push("Consider limiting the scope to read-only access")
			recommendations.push("Set a shorter duration for this permission")
			recommendations.push("Enable additional monitoring for this permission")
		}

		if (level === "medium") {
			recommendations.push("Review the necessity of the requested scope")
			recommendations.push("Consider setting usage quotas")
		}

		if (factors.includes("Command execution access")) {
			recommendations.push("Restrict to specific allowed commands")
			recommendations.push("Enable command logging and monitoring")
		}

		if (factors.includes("File system access")) {
			recommendations.push("Limit access to specific directories")
			recommendations.push("Set file size limits")
		}

		if (factors.includes("Network access")) {
			recommendations.push("Restrict to specific domains")
			recommendations.push("Monitor network requests")
		}

		return recommendations
	}

	/**
	 * Grant a permission based on an approved request
	 */
	grantPermission(
		requestId: string,
		approvedScope?: PermissionScope,
		approvedDuration?: number,
		approvedQuota?: UsageQuota,
		userApproved: boolean = true,
	): Permission {
		const request = this.pendingRequests.get(requestId)
		if (!request) {
			throw new Error(`Permission request ${requestId} not found`)
		}

		const now = Date.now()
		const duration = approvedDuration || request.requestedDuration || this.policy.defaultDuration
		const scope = approvedScope || request.requestedScope
		const quota = approvedQuota || request.requestedQuota || this.policy.defaultQuota

		const permission: Permission = {
			id: this.generatePermissionId(),
			serverName: request.serverName,
			toolName: request.toolName,
			resourcePattern: request.resourcePattern,
			type: request.type,
			scope,
			status: PermissionStatus.ACTIVE,
			grantedAt: now,
			expiresAt: now + duration,
			usageCount: 0,
			quota,
			resourceConstraints: request.resourceConstraints,
			reason: request.reason,
			userApproved,
			autoGranted: !userApproved,
			riskLevel: request.riskAssessment.level,
			canDelegate: this.policy.allowDelegation && scope !== PermissionScope.FULL_ACCESS,
			auditTrail: [
				{
					timestamp: now,
					action: "granted",
					details: `Permission granted with scope: ${scope}, duration: ${duration}ms`,
				},
			],
		}

		this.permissions.set(permission.id, permission)
		this.pendingRequests.delete(requestId)

		return permission
	}

	/**
	 * Validate if a permission allows a specific action
	 */
	validatePermission(
		serverName: string,
		toolName?: string,
		resourcePattern?: string,
		type: PermissionType = PermissionType.TOOL_EXECUTION,
		requiredScope: PermissionScope = PermissionScope.EXECUTE,
	): PermissionValidationResult {
		const now = Date.now()
		const violations: string[] = []
		const suggestedActions: string[] = []

		// Find matching permissions
		const matchingPermissions = Array.from(this.permissions.values()).filter((permission) => {
			if (permission.serverName !== serverName) return false
			if (toolName && permission.toolName && permission.toolName !== toolName) return false
			if (
				resourcePattern &&
				permission.resourcePattern &&
				!this.matchesPattern(resourcePattern, permission.resourcePattern)
			)
				return false
			if (permission.type !== type) return false
			return true
		})

		if (matchingPermissions.length === 0) {
			return {
				allowed: false,
				reason: "No matching permission found",
				violations: ["No permission exists for this action"],
				suggestedActions: ["Request permission for this action"],
				requiresApproval: this.policy.requireApprovalFor.includes(type),
				riskLevel: "medium",
			}
		}

		// Find the best matching active permission
		const activePermissions = matchingPermissions.filter((p) => p.status === PermissionStatus.ACTIVE)
		if (activePermissions.length === 0) {
			return {
				allowed: false,
				reason: "No active permissions found",
				violations: ["All matching permissions are inactive"],
				suggestedActions: ["Renew expired permissions"],
				requiresApproval: true,
				riskLevel: "medium",
			}
		}

		// Check for expired permissions
		const validPermissions = activePermissions.filter((p) => !p.expiresAt || p.expiresAt > now)
		if (validPermissions.length === 0) {
			// Mark expired permissions
			activePermissions.forEach((p) => {
				if (p.expiresAt && p.expiresAt <= now) {
					p.status = PermissionStatus.EXPIRED
					p.auditTrail.push({
						timestamp: now,
						action: "expired",
						details: "Permission expired",
					})
				}
			})

			return {
				allowed: false,
				reason: "All matching permissions have expired",
				violations: ["Permissions expired"],
				suggestedActions: ["Renew expired permissions"],
				requiresApproval: true,
				riskLevel: "low",
			}
		}

		// Find permission with sufficient scope
		const scopeHierarchy = [
			PermissionScope.READ_ONLY,
			PermissionScope.EXECUTE,
			PermissionScope.ADMIN,
			PermissionScope.FULL_ACCESS,
		]

		const requiredScopeIndex = scopeHierarchy.indexOf(requiredScope)
		const sufficientPermissions = validPermissions.filter((p) => {
			const permissionScopeIndex = scopeHierarchy.indexOf(p.scope)
			return permissionScopeIndex >= requiredScopeIndex
		})

		if (sufficientPermissions.length === 0) {
			return {
				allowed: false,
				reason: "Insufficient permission scope",
				violations: [
					`Required scope: ${requiredScope}, available: ${validPermissions.map((p) => p.scope).join(", ")}`,
				],
				suggestedActions: ["Request higher permission scope"],
				requiresApproval: true,
				riskLevel: "medium",
			}
		}

		// Select the best permission (highest scope, most recent)
		const bestPermission = sufficientPermissions.sort((a, b) => {
			const aScopeIndex = scopeHierarchy.indexOf(a.scope)
			const bScopeIndex = scopeHierarchy.indexOf(b.scope)
			if (aScopeIndex !== bScopeIndex) return bScopeIndex - aScopeIndex
			return b.grantedAt - a.grantedAt
		})[0]

		// Check quota limits
		if (bestPermission.quota) {
			const quotaViolations = this.checkQuotaLimits(bestPermission)
			if (quotaViolations.length > 0) {
				return {
					allowed: false,
					reason: "Quota limits exceeded",
					violations: quotaViolations,
					suggestedActions: ["Wait for quota reset", "Request higher quota"],
					requiresApproval: false,
					riskLevel: "low",
				}
			}
		}

		// Check time constraints
		if (bestPermission.timeConstraints) {
			const timeViolations = this.checkTimeConstraints(bestPermission.timeConstraints)
			if (timeViolations.length > 0) {
				return {
					allowed: false,
					reason: "Time constraints not met",
					violations: timeViolations,
					suggestedActions: ["Wait for allowed time window"],
					requiresApproval: false,
					riskLevel: "low",
				}
			}
		}

		// Check conditional rules
		if (bestPermission.conditionalRules) {
			const conditionalViolations = this.checkConditionalRules(bestPermission.conditionalRules)
			if (conditionalViolations.length > 0) {
				return {
					allowed: false,
					reason: "Conditional rules not satisfied",
					violations: conditionalViolations,
					suggestedActions: ["Ensure conditions are met"],
					requiresApproval: false,
					riskLevel: "medium",
				}
			}
		}

		return {
			allowed: true,
			permission: bestPermission,
			reason: "Permission validated successfully",
			riskLevel: bestPermission.riskLevel,
		}
	}

	/**
	 * Record permission usage
	 */
	recordUsage(permissionId: string, context?: Record<string, unknown>): void {
		const permission = this.permissions.get(permissionId)
		if (!permission) return

		const now = Date.now()
		permission.usageCount++
		permission.lastUsedAt = now
		permission.auditTrail.push({
			timestamp: now,
			action: "used",
			details: `Permission used (count: ${permission.usageCount})`,
			context,
		})
	}

	/**
	 * Revoke a permission
	 */
	revokePermission(permissionId: string, reason?: string): boolean {
		const permission = this.permissions.get(permissionId)
		if (!permission) return false

		permission.status = PermissionStatus.REVOKED
		permission.auditTrail.push({
			timestamp: Date.now(),
			action: "revoked",
			details: reason || "Permission revoked",
		})

		return true
	}

	/**
	 * Get all permissions for a server
	 */
	getPermissionsForServer(serverName: string): Permission[] {
		return Array.from(this.permissions.values()).filter((p) => p.serverName === serverName)
	}

	/**
	 * Get pending requests
	 */
	getPendingRequests(): PermissionRequest[] {
		const now = Date.now()
		// Clean up expired requests
		for (const [id, request] of this.pendingRequests.entries()) {
			if (request.expiresAt && request.expiresAt <= now) {
				this.pendingRequests.delete(id)
			}
		}
		return Array.from(this.pendingRequests.values())
	}

	/**
	 * Clean up expired permissions
	 */
	cleanupExpiredPermissions(): number {
		const now = Date.now()
		let cleanedCount = 0

		for (const [id, permission] of this.permissions.entries()) {
			if (permission.expiresAt && permission.expiresAt <= now && permission.status === PermissionStatus.ACTIVE) {
				permission.status = PermissionStatus.EXPIRED
				permission.auditTrail.push({
					timestamp: now,
					action: "expired",
					details: "Permission expired during cleanup",
				})
				cleanedCount++
			}
		}

		return cleanedCount
	}

	/**
	 * Helper methods
	 */
	private matchesPattern(resource: string, pattern: string): boolean {
		// Simple glob-like pattern matching
		const regexPattern = pattern.replace(/\*/g, ".*").replace(/\?/g, ".")
		return new RegExp(`^${regexPattern}$`).test(resource)
	}

	private checkQuotaLimits(permission: Permission): string[] {
		const violations: string[] = []
		const quota = permission.quota
		if (!quota) return violations

		if (quota.maxExecutions && permission.usageCount >= quota.maxExecutions) {
			violations.push(`Maximum executions exceeded: ${permission.usageCount}/${quota.maxExecutions}`)
		}

		// Additional quota checks would require time-based tracking
		// This is a simplified implementation

		return violations
	}

	private checkTimeConstraints(constraints: TimeConstraints): string[] {
		const violations: string[] = []
		const now = Date.now()

		if (constraints.validFrom && now < constraints.validFrom) {
			violations.push("Permission not yet valid")
		}

		if (constraints.validUntil && now > constraints.validUntil) {
			violations.push("Permission validity period ended")
		}

		if (constraints.allowedHours) {
			const currentHour = new Date().getHours()
			if (!constraints.allowedHours.includes(currentHour)) {
				violations.push(
					`Current hour ${currentHour} not in allowed hours: ${constraints.allowedHours.join(", ")}`,
				)
			}
		}

		if (constraints.allowedDays) {
			const currentDay = new Date().getDay()
			if (!constraints.allowedDays.includes(currentDay)) {
				violations.push(`Current day ${currentDay} not in allowed days: ${constraints.allowedDays.join(", ")}`)
			}
		}

		return violations
	}

	private checkConditionalRules(rules: ConditionalRules[]): string[] {
		const violations: string[] = []

		for (const rule of rules) {
			switch (rule.condition) {
				case PermissionCondition.USER_PRESENCE:
					// This would require integration with user presence detection
					break
				case PermissionCondition.WORKSPACE_BASED:
					// This would require workspace context
					break
				// Add other conditional checks as needed
			}
		}

		return violations
	}
}
