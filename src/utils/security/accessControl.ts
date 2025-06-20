/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Role-based access control (RBAC) implementation for MCP tools.
 * Provides hierarchical permission management and role-based security.
 */

import { z } from "zod"
import { PermissionScope, PermissionType, Permission, PermissionManager } from "./permissionManager"

/**
 * User roles with hierarchical permissions
 */
export enum UserRole {
	GUEST = "guest",
	USER = "user",
	DEVELOPER = "developer",
	ADMIN = "admin",
	SUPER_ADMIN = "super_admin",
}

/**
 * Role capabilities define what each role can do
 */
export interface RoleCapabilities {
	canExecuteTools: boolean
	canAccessResources: boolean
	canModifyFiles: boolean
	canExecuteCommands: boolean
	canAccessNetwork: boolean
	canManagePermissions: boolean
	canDelegatePermissions: boolean
	canViewAuditLogs: boolean
	maxPermissionDuration: number
	allowedScopes: PermissionScope[]
	allowedTypes: PermissionType[]
}

/**
 * User context for access control decisions
 */
export interface UserContext {
	userId?: string
	role: UserRole
	sessionId?: string
	ipAddress?: string
	userAgent?: string
	workspaceId?: string
	isAuthenticated: boolean
	lastActivity: number
}

/**
 * Access control policy
 */
export interface AccessControlPolicy {
	defaultRole: UserRole
	requireAuthentication: boolean
	sessionTimeout: number
	maxConcurrentSessions: number
	roleCapabilities: Record<UserRole, RoleCapabilities>
	inheritanceRules: Record<UserRole, UserRole[]>
}

/**
 * Access control decision result
 */
export interface AccessControlResult {
	allowed: boolean
	role: UserRole
	capabilities: RoleCapabilities
	reason: string
	restrictions?: string[]
	recommendations?: string[]
}

/**
 * Zod schemas
 */
export const UserRoleSchema = z.nativeEnum(UserRole)

export const RoleCapabilitiesSchema = z.object({
	canExecuteTools: z.boolean(),
	canAccessResources: z.boolean(),
	canModifyFiles: z.boolean(),
	canExecuteCommands: z.boolean(),
	canAccessNetwork: z.boolean(),
	canManagePermissions: z.boolean(),
	canDelegatePermissions: z.boolean(),
	canViewAuditLogs: z.boolean(),
	maxPermissionDuration: z.number().positive(),
	allowedScopes: z.array(z.nativeEnum(PermissionScope)),
	allowedTypes: z.array(z.nativeEnum(PermissionType)),
})

export const UserContextSchema = z.object({
	userId: z.string().optional(),
	role: UserRoleSchema,
	sessionId: z.string().optional(),
	ipAddress: z.string().optional(),
	userAgent: z.string().optional(),
	workspaceId: z.string().optional(),
	isAuthenticated: z.boolean(),
	lastActivity: z.number(),
})

export const AccessControlPolicySchema = z.object({
	defaultRole: UserRoleSchema,
	requireAuthentication: z.boolean(),
	sessionTimeout: z.number().positive(),
	maxConcurrentSessions: z.number().positive(),
	roleCapabilities: z.record(UserRoleSchema, RoleCapabilitiesSchema),
	inheritanceRules: z.record(UserRoleSchema, z.array(UserRoleSchema)),
})

/**
 * Default role capabilities
 */
export const DEFAULT_ROLE_CAPABILITIES: Record<UserRole, RoleCapabilities> = {
	[UserRole.GUEST]: {
		canExecuteTools: false,
		canAccessResources: true,
		canModifyFiles: false,
		canExecuteCommands: false,
		canAccessNetwork: false,
		canManagePermissions: false,
		canDelegatePermissions: false,
		canViewAuditLogs: false,
		maxPermissionDuration: 60 * 60 * 1000, // 1 hour
		allowedScopes: [PermissionScope.READ_ONLY],
		allowedTypes: [PermissionType.RESOURCE_ACCESS],
	},
	[UserRole.USER]: {
		canExecuteTools: true,
		canAccessResources: true,
		canModifyFiles: false,
		canExecuteCommands: false,
		canAccessNetwork: false,
		canManagePermissions: false,
		canDelegatePermissions: false,
		canViewAuditLogs: false,
		maxPermissionDuration: 8 * 60 * 60 * 1000, // 8 hours
		allowedScopes: [PermissionScope.READ_ONLY, PermissionScope.EXECUTE],
		allowedTypes: [PermissionType.TOOL_EXECUTION, PermissionType.RESOURCE_ACCESS],
	},
	[UserRole.DEVELOPER]: {
		canExecuteTools: true,
		canAccessResources: true,
		canModifyFiles: true,
		canExecuteCommands: true,
		canAccessNetwork: true,
		canManagePermissions: false,
		canDelegatePermissions: true,
		canViewAuditLogs: true,
		maxPermissionDuration: 24 * 60 * 60 * 1000, // 24 hours
		allowedScopes: [PermissionScope.READ_ONLY, PermissionScope.EXECUTE, PermissionScope.ADMIN],
		allowedTypes: [
			PermissionType.TOOL_EXECUTION,
			PermissionType.RESOURCE_ACCESS,
			PermissionType.FILE_SYSTEM,
			PermissionType.COMMAND_EXECUTION,
			PermissionType.NETWORK,
		],
	},
	[UserRole.ADMIN]: {
		canExecuteTools: true,
		canAccessResources: true,
		canModifyFiles: true,
		canExecuteCommands: true,
		canAccessNetwork: true,
		canManagePermissions: true,
		canDelegatePermissions: true,
		canViewAuditLogs: true,
		maxPermissionDuration: 7 * 24 * 60 * 60 * 1000, // 7 days
		allowedScopes: [
			PermissionScope.READ_ONLY,
			PermissionScope.EXECUTE,
			PermissionScope.ADMIN,
			PermissionScope.FULL_ACCESS,
		],
		allowedTypes: [
			PermissionType.TOOL_EXECUTION,
			PermissionType.RESOURCE_ACCESS,
			PermissionType.FILE_SYSTEM,
			PermissionType.COMMAND_EXECUTION,
			PermissionType.NETWORK,
		],
	},
	[UserRole.SUPER_ADMIN]: {
		canExecuteTools: true,
		canAccessResources: true,
		canModifyFiles: true,
		canExecuteCommands: true,
		canAccessNetwork: true,
		canManagePermissions: true,
		canDelegatePermissions: true,
		canViewAuditLogs: true,
		maxPermissionDuration: 30 * 24 * 60 * 60 * 1000, // 30 days
		allowedScopes: [
			PermissionScope.READ_ONLY,
			PermissionScope.EXECUTE,
			PermissionScope.ADMIN,
			PermissionScope.FULL_ACCESS,
		],
		allowedTypes: [
			PermissionType.TOOL_EXECUTION,
			PermissionType.RESOURCE_ACCESS,
			PermissionType.FILE_SYSTEM,
			PermissionType.COMMAND_EXECUTION,
			PermissionType.NETWORK,
		],
	},
}

/**
 * Default access control policy
 */
export const DEFAULT_ACCESS_CONTROL_POLICY: AccessControlPolicy = {
	defaultRole: UserRole.USER,
	requireAuthentication: false,
	sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
	maxConcurrentSessions: 5,
	roleCapabilities: DEFAULT_ROLE_CAPABILITIES,
	inheritanceRules: {
		[UserRole.GUEST]: [],
		[UserRole.USER]: [UserRole.GUEST],
		[UserRole.DEVELOPER]: [UserRole.USER, UserRole.GUEST],
		[UserRole.ADMIN]: [UserRole.DEVELOPER, UserRole.USER, UserRole.GUEST],
		[UserRole.SUPER_ADMIN]: [UserRole.ADMIN, UserRole.DEVELOPER, UserRole.USER, UserRole.GUEST],
	},
}

/**
 * Access control manager
 */
export class AccessControlManager {
	private policy: AccessControlPolicy
	private activeSessions: Map<string, UserContext> = new Map()
	private permissionManager: PermissionManager

	constructor(permissionManager: PermissionManager, policy: AccessControlPolicy = DEFAULT_ACCESS_CONTROL_POLICY) {
		this.permissionManager = permissionManager
		this.policy = policy
	}

	/**
	 * Create or update user context
	 */
	createUserContext(
		role: UserRole = this.policy.defaultRole,
		options: {
			userId?: string
			sessionId?: string
			ipAddress?: string
			userAgent?: string
			workspaceId?: string
			isAuthenticated?: boolean
		} = {},
	): UserContext {
		const context: UserContext = {
			role,
			isAuthenticated: options.isAuthenticated ?? !this.policy.requireAuthentication,
			lastActivity: Date.now(),
			...options,
		}

		if (context.sessionId) {
			this.activeSessions.set(context.sessionId, context)
		}

		return context
	}

	/**
	 * Get user context by session ID
	 */
	getUserContext(sessionId: string): UserContext | undefined {
		const context = this.activeSessions.get(sessionId)
		if (!context) return undefined

		// Check session timeout
		const now = Date.now()
		if (now - context.lastActivity > this.policy.sessionTimeout) {
			this.activeSessions.delete(sessionId)
			return undefined
		}

		// Update last activity
		context.lastActivity = now
		return context
	}

	/**
	 * Check if user has permission for an action
	 */
	checkAccess(
		context: UserContext,
		action: {
			type: PermissionType
			scope: PermissionScope
			serverName: string
			toolName?: string
			resourcePattern?: string
		},
	): AccessControlResult {
		const capabilities = this.getRoleCapabilities(context.role)
		const restrictions: string[] = []
		const recommendations: string[] = []

		// Check authentication requirement
		if (this.policy.requireAuthentication && !context.isAuthenticated) {
			return {
				allowed: false,
				role: context.role,
				capabilities,
				reason: "Authentication required",
				restrictions: ["User must be authenticated"],
				recommendations: ["Please authenticate to access this resource"],
			}
		}

		// Check if role allows the permission type
		if (!capabilities.allowedTypes.includes(action.type)) {
			return {
				allowed: false,
				role: context.role,
				capabilities,
				reason: `Role ${context.role} not allowed to perform ${action.type}`,
				restrictions: [`Permission type ${action.type} not allowed for role ${context.role}`],
				recommendations: [`Request role elevation to access ${action.type}`],
			}
		}

		// Check if role allows the permission scope
		if (!capabilities.allowedScopes.includes(action.scope)) {
			return {
				allowed: false,
				role: context.role,
				capabilities,
				reason: `Role ${context.role} not allowed scope ${action.scope}`,
				restrictions: [`Permission scope ${action.scope} not allowed for role ${context.role}`],
				recommendations: [`Request role elevation for ${action.scope} access`],
			}
		}

		// Check specific capability requirements
		switch (action.type) {
			case PermissionType.TOOL_EXECUTION:
				if (!capabilities.canExecuteTools) {
					restrictions.push("Tool execution not allowed for this role")
				}
				break
			case PermissionType.RESOURCE_ACCESS:
				if (!capabilities.canAccessResources) {
					restrictions.push("Resource access not allowed for this role")
				}
				break
			case PermissionType.FILE_SYSTEM:
				if (!capabilities.canModifyFiles) {
					restrictions.push("File system access not allowed for this role")
				}
				break
			case PermissionType.COMMAND_EXECUTION:
				if (!capabilities.canExecuteCommands) {
					restrictions.push("Command execution not allowed for this role")
				}
				break
			case PermissionType.NETWORK:
				if (!capabilities.canAccessNetwork) {
					restrictions.push("Network access not allowed for this role")
				}
				break
		}

		if (restrictions.length > 0) {
			return {
				allowed: false,
				role: context.role,
				capabilities,
				reason: "Insufficient role capabilities",
				restrictions,
				recommendations: ["Request role elevation or permission delegation"],
			}
		}

		// Check existing permissions through permission manager
		const permissionResult = this.permissionManager.validatePermission(
			action.serverName,
			action.toolName,
			action.resourcePattern,
			action.type,
			action.scope,
		)

		if (!permissionResult.allowed) {
			// Role allows it, but no specific permission exists
			recommendations.push("Request specific permission for this action")
		}

		return {
			allowed: true,
			role: context.role,
			capabilities,
			reason: "Access granted based on role capabilities",
			recommendations: recommendations.length > 0 ? recommendations : undefined,
		}
	}

	/**
	 * Get effective capabilities for a role (including inherited capabilities)
	 */
	getRoleCapabilities(role: UserRole): RoleCapabilities {
		const baseCapabilities = this.policy.roleCapabilities[role]
		const inheritedRoles = this.policy.inheritanceRules[role] || []

		// Merge capabilities from inherited roles
		let effectiveCapabilities = { ...baseCapabilities }

		for (const inheritedRole of inheritedRoles) {
			const inheritedCapabilities = this.policy.roleCapabilities[inheritedRole]
			if (inheritedCapabilities) {
				// Merge boolean capabilities (OR operation)
				effectiveCapabilities.canExecuteTools =
					effectiveCapabilities.canExecuteTools || inheritedCapabilities.canExecuteTools
				effectiveCapabilities.canAccessResources =
					effectiveCapabilities.canAccessResources || inheritedCapabilities.canAccessResources
				effectiveCapabilities.canModifyFiles =
					effectiveCapabilities.canModifyFiles || inheritedCapabilities.canModifyFiles
				effectiveCapabilities.canExecuteCommands =
					effectiveCapabilities.canExecuteCommands || inheritedCapabilities.canExecuteCommands
				effectiveCapabilities.canAccessNetwork =
					effectiveCapabilities.canAccessNetwork || inheritedCapabilities.canAccessNetwork
				effectiveCapabilities.canManagePermissions =
					effectiveCapabilities.canManagePermissions || inheritedCapabilities.canManagePermissions
				effectiveCapabilities.canDelegatePermissions =
					effectiveCapabilities.canDelegatePermissions || inheritedCapabilities.canDelegatePermissions
				effectiveCapabilities.canViewAuditLogs =
					effectiveCapabilities.canViewAuditLogs || inheritedCapabilities.canViewAuditLogs

				// Merge arrays (union)
				effectiveCapabilities.allowedScopes = [
					...new Set([...effectiveCapabilities.allowedScopes, ...inheritedCapabilities.allowedScopes]),
				]
				effectiveCapabilities.allowedTypes = [
					...new Set([...effectiveCapabilities.allowedTypes, ...inheritedCapabilities.allowedTypes]),
				]

				// Take maximum duration
				effectiveCapabilities.maxPermissionDuration = Math.max(
					effectiveCapabilities.maxPermissionDuration,
					inheritedCapabilities.maxPermissionDuration,
				)
			}
		}

		return effectiveCapabilities
	}

	/**
	 * Elevate user role temporarily
	 */
	elevateRole(context: UserContext, targetRole: UserRole, duration: number, reason: string): boolean {
		const currentCapabilities = this.getRoleCapabilities(context.role)
		const targetCapabilities = this.getRoleCapabilities(targetRole)

		// Check if current role can delegate to target role
		if (!currentCapabilities.canDelegatePermissions) {
			return false
		}

		// Check if target role is within allowed elevation path
		const roleHierarchy = [UserRole.GUEST, UserRole.USER, UserRole.DEVELOPER, UserRole.ADMIN, UserRole.SUPER_ADMIN]
		const currentIndex = roleHierarchy.indexOf(context.role)
		const targetIndex = roleHierarchy.indexOf(targetRole)

		// Only allow elevation to higher roles within reasonable limits
		if (targetIndex <= currentIndex || targetIndex - currentIndex > 2) {
			return false
		}

		// Create temporary elevated context
		// This would typically involve creating a time-limited permission
		// For now, we'll just update the context
		context.role = targetRole

		// Log the elevation
		console.log(`Role elevated from ${context.role} to ${targetRole} for ${duration}ms. Reason: ${reason}`)

		return true
	}

	/**
	 * Clean up expired sessions
	 */
	cleanupExpiredSessions(): number {
		const now = Date.now()
		let cleanedCount = 0

		for (const [sessionId, context] of this.activeSessions.entries()) {
			if (now - context.lastActivity > this.policy.sessionTimeout) {
				this.activeSessions.delete(sessionId)
				cleanedCount++
			}
		}

		return cleanedCount
	}

	/**
	 * Get active sessions count
	 */
	getActiveSessionsCount(): number {
		this.cleanupExpiredSessions()
		return this.activeSessions.size
	}

	/**
	 * Check if user can create new session
	 */
	canCreateSession(): boolean {
		return this.getActiveSessionsCount() < this.policy.maxConcurrentSessions
	}

	/**
	 * Revoke session
	 */
	revokeSession(sessionId: string): boolean {
		return this.activeSessions.delete(sessionId)
	}

	/**
	 * Get all active sessions (admin only)
	 */
	getActiveSessions(requestingContext: UserContext): UserContext[] {
		const capabilities = this.getRoleCapabilities(requestingContext.role)
		if (!capabilities.canViewAuditLogs) {
			return []
		}

		this.cleanupExpiredSessions()
		return Array.from(this.activeSessions.values())
	}

	/**
	 * Update policy
	 */
	updatePolicy(newPolicy: Partial<AccessControlPolicy>): void {
		this.policy = { ...this.policy, ...newPolicy }
	}

	/**
	 * Get current policy
	 */
	getPolicy(): AccessControlPolicy {
		return { ...this.policy }
	}
}
