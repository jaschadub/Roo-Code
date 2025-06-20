/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Enhanced MCP Hub with granular permission management.
 * Replaces the weak binary `alwaysAllow` system with time-limited, scope-based permissions.
 */

import * as vscode from "vscode"
import { McpHub, McpConnection } from "./McpHub"
import { ClineProvider } from "../../core/webview/ClineProvider"
import {
	PermissionManager,
	PermissionScope,
	PermissionType,
	PermissionStatus,
	Permission,
	PermissionRequest,
	PermissionValidationResult,
	AccessControlManager,
	UserRole,
	UserContext,
	PermissionStore,
	AuditLogger,
	AuditEventType,
	AuditSeverity,
} from "../../utils/security"
import { McpTool, McpToolCallResponse, McpResourceResponse } from "../../shared/mcp"

/**
 * Enhanced permission configuration for MCP servers
 */
export interface EnhancedServerConfig {
	// Legacy support
	alwaysAllow?: string[]

	// Enhanced permission settings
	permissions?: {
		enabled: boolean
		defaultScope: PermissionScope
		defaultDuration: number
		requireApproval: boolean
		autoGrantLowRisk: boolean
		maxConcurrentPermissions: number
	}

	// Access control settings
	accessControl?: {
		enabled: boolean
		defaultRole: UserRole
		requireAuthentication: boolean
	}

	// Audit settings
	audit?: {
		enabled: boolean
		logLevel: AuditSeverity
		retentionDays: number
	}
}

/**
 * Permission request context for user approval
 */
export interface PermissionRequestContext {
	request: PermissionRequest
	serverName: string
	toolName?: string
	resourcePattern?: string
	userContext: UserContext
	riskAssessment: {
		level: "low" | "medium" | "high"
		factors: string[]
		recommendations: string[]
	}
}

/**
 * Enhanced MCP Hub with permission management
 */
export class EnhancedMcpHub extends McpHub {
	private permissionManager: PermissionManager
	private accessControlManager: AccessControlManager
	private permissionStore: PermissionStore
	private auditLogger: AuditLogger
	private userContext: UserContext
	private migrationCompleted: boolean = false

	constructor(provider: ClineProvider) {
		super(provider)

		// Initialize permission management components
		this.permissionManager = new PermissionManager()
		this.accessControlManager = new AccessControlManager(this.permissionManager)
		this.permissionStore = new PermissionStore()
		this.auditLogger = new AuditLogger()

		// Create default user context
		this.userContext = this.accessControlManager.createUserContext(UserRole.USER, {
			userId: "default_user",
			sessionId: `session_${Date.now()}`,
		})

		this.initializeEnhancedSecurity()
	}

	/**
	 * Initialize enhanced security components
	 */
	private async initializeEnhancedSecurity(): Promise<void> {
		try {
			await this.permissionStore.initialize()
			await this.auditLogger.initialize()
			await this.loadPersistedPermissions()
			await this.migrateFromAlwaysAllow()

			await this.auditLogger.logEvent({
				type: AuditEventType.SYSTEM_ERROR,
				severity: AuditSeverity.LOW,
				success: true,
				message: "Enhanced MCP Hub initialized successfully",
			})
		} catch (error) {
			console.error("Failed to initialize enhanced security:", error)
			await this.auditLogger.logEvent({
				type: AuditEventType.SYSTEM_ERROR,
				severity: AuditSeverity.HIGH,
				success: false,
				message: `Failed to initialize enhanced security: ${error instanceof Error ? error.message : error}`,
			})
		}
	}

	/**
	 * Load persisted permissions from storage
	 */
	private async loadPersistedPermissions(): Promise<void> {
		try {
			const permissions = await this.permissionStore.loadPermissions()
			for (const permission of permissions) {
				// Validate and restore permissions
				if (
					permission.status === PermissionStatus.ACTIVE &&
					(!permission.expiresAt || permission.expiresAt > Date.now())
				) {
					// Permission is still valid
					continue
				} else if (permission.expiresAt && permission.expiresAt <= Date.now()) {
					// Mark as expired
					permission.status = PermissionStatus.EXPIRED
					await this.permissionStore.savePermission(permission)
				}
			}
		} catch (error) {
			console.error("Failed to load persisted permissions:", error)
		}
	}

	/**
	 * Migrate existing alwaysAllow configurations to the new permission system
	 */
	private async migrateFromAlwaysAllow(): Promise<void> {
		if (this.migrationCompleted) return

		try {
			const servers = this.getAllServers()
			let migratedCount = 0

			for (const server of servers) {
				const config = JSON.parse(server.config)
				if (config.alwaysAllow && Array.isArray(config.alwaysAllow) && config.alwaysAllow.length > 0) {
					await this.migrateServerPermissions(server.name, config.alwaysAllow, server.source || "global")
					migratedCount++
				}
			}

			this.migrationCompleted = true

			await this.auditLogger.logEvent({
				type: AuditEventType.POLICY_CHANGED,
				severity: AuditSeverity.MEDIUM,
				success: true,
				message: `Migration completed: ${migratedCount} servers migrated from alwaysAllow to enhanced permissions`,
				details: { migratedServers: migratedCount },
			})
		} catch (error) {
			console.error("Failed to migrate from alwaysAllow:", error)
			await this.auditLogger.logEvent({
				type: AuditEventType.SYSTEM_ERROR,
				severity: AuditSeverity.HIGH,
				success: false,
				message: `Migration failed: ${error instanceof Error ? error.message : error}`,
			})
		}
	}

	/**
	 * Migrate a server's alwaysAllow tools to permissions
	 */
	private async migrateServerPermissions(
		serverName: string,
		alwaysAllowTools: string[],
		source: "global" | "project",
	): Promise<void> {
		for (const toolName of alwaysAllowTools) {
			try {
				// Create a permission request for the tool
				const request = this.permissionManager.createPermissionRequest(
					serverName,
					toolName,
					undefined,
					PermissionType.TOOL_EXECUTION,
					PermissionScope.EXECUTE,
					`Migrated from alwaysAllow configuration`,
					{
						duration: 30 * 24 * 60 * 60 * 1000, // 30 days
					},
				)

				// Auto-grant the permission (since it was previously always allowed)
				const permission = this.permissionManager.grantPermission(
					request.id,
					PermissionScope.EXECUTE,
					30 * 24 * 60 * 60 * 1000, // 30 days
					undefined,
					false, // auto-granted, not user-approved
				)

				// Save to storage
				await this.permissionStore.savePermission(permission)

				await this.auditLogger.logPermissionGranted(
					serverName,
					toolName,
					permission.id,
					this.userContext.userId,
				)
			} catch (error) {
				console.error(`Failed to migrate permission for ${serverName}:${toolName}:`, error)
			}
		}
	}

	/**
	 * Enhanced tool execution with permission validation
	 */
	override async callTool(
		serverName: string,
		toolName: string,
		toolArguments?: Record<string, unknown>,
		source?: "global" | "project",
	): Promise<McpToolCallResponse> {
		const startTime = Date.now()

		try {
			// Check access control
			const accessResult = this.accessControlManager.checkAccess(this.userContext, {
				type: PermissionType.TOOL_EXECUTION,
				scope: PermissionScope.EXECUTE,
				serverName,
				toolName,
			})

			if (!accessResult.allowed) {
				await this.auditLogger.logPermissionDenied(
					serverName,
					toolName,
					accessResult.reason,
					this.userContext.userId,
				)
				throw new Error(`Access denied: ${accessResult.reason}`)
			}

			// Validate specific permission
			const permissionResult = this.permissionManager.validatePermission(
				serverName,
				toolName,
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
			)

			if (!permissionResult.allowed) {
				// Check if we should request permission
				if (permissionResult.requiresApproval) {
					const approved = await this.requestPermissionApproval(
						serverName,
						toolName,
						PermissionType.TOOL_EXECUTION,
						PermissionScope.EXECUTE,
						`Tool execution: ${toolName}`,
					)

					if (!approved) {
						await this.auditLogger.logPermissionDenied(
							serverName,
							toolName,
							"User denied permission request",
							this.userContext.userId,
						)
						throw new Error("Permission denied by user")
					}
				} else {
					await this.auditLogger.logPermissionDenied(
						serverName,
						toolName,
						permissionResult.reason,
						this.userContext.userId,
					)
					throw new Error(`Permission denied: ${permissionResult.reason}`)
				}
			}

			// Record permission usage
			if (permissionResult.permission) {
				this.permissionManager.recordUsage(permissionResult.permission.id, {
					toolName,
					arguments: toolArguments,
					timestamp: startTime,
				})
				await this.permissionStore.savePermission(permissionResult.permission)
			}

			// Execute the tool using parent implementation
			const result = await super.callTool(serverName, toolName, toolArguments, source)

			// Log successful execution
			await this.auditLogger.logToolExecution(serverName, toolName, true, this.userContext.userId, {
				executionTime: Date.now() - startTime,
				argumentsProvided: !!toolArguments,
			})

			return result
		} catch (error) {
			// Log failed execution
			await this.auditLogger.logToolExecution(serverName, toolName, false, this.userContext.userId, {
				executionTime: Date.now() - startTime,
				error: error instanceof Error ? error.message : String(error),
			})

			throw error
		}
	}

	/**
	 * Enhanced resource access with permission validation
	 */
	override async readResource(
		serverName: string,
		uri: string,
		source?: "global" | "project",
	): Promise<McpResourceResponse> {
		try {
			// Check access control
			const accessResult = this.accessControlManager.checkAccess(this.userContext, {
				type: PermissionType.RESOURCE_ACCESS,
				scope: PermissionScope.READ_ONLY,
				serverName,
				resourcePattern: uri,
			})

			if (!accessResult.allowed) {
				await this.auditLogger.logEvent({
					type: AuditEventType.PERMISSION_DENIED,
					severity: AuditSeverity.MEDIUM,
					serverName,
					resourceUri: uri,
					userId: this.userContext.userId,
					success: false,
					message: `Resource access denied: ${accessResult.reason}`,
				})
				throw new Error(`Access denied: ${accessResult.reason}`)
			}

			// Validate specific permission
			const permissionResult = this.permissionManager.validatePermission(
				serverName,
				undefined,
				uri,
				PermissionType.RESOURCE_ACCESS,
				PermissionScope.READ_ONLY,
			)

			if (!permissionResult.allowed && permissionResult.requiresApproval) {
				const approved = await this.requestPermissionApproval(
					serverName,
					undefined,
					PermissionType.RESOURCE_ACCESS,
					PermissionScope.READ_ONLY,
					`Resource access: ${uri}`,
					uri,
				)

				if (!approved) {
					await this.auditLogger.logEvent({
						type: AuditEventType.PERMISSION_DENIED,
						severity: AuditSeverity.MEDIUM,
						serverName,
						resourceUri: uri,
						userId: this.userContext.userId,
						success: false,
						message: "Resource access denied by user",
					})
					throw new Error("Permission denied by user")
				}
			}

			// Execute the resource access using parent implementation
			const result = await super.readResource(serverName, uri, source)

			// Log successful access
			await this.auditLogger.logEvent({
				type: AuditEventType.RESOURCE_ACCESS,
				severity: AuditSeverity.LOW,
				serverName,
				resourceUri: uri,
				userId: this.userContext.userId,
				success: true,
				message: `Resource accessed successfully: ${uri}`,
			})

			return result
		} catch (error) {
			// Log failed access
			await this.auditLogger.logEvent({
				type: AuditEventType.RESOURCE_ACCESS,
				severity: AuditSeverity.MEDIUM,
				serverName,
				resourceUri: uri,
				userId: this.userContext.userId,
				success: false,
				message: `Resource access failed: ${error instanceof Error ? error.message : error}`,
			})

			throw error
		}
	}

	/**
	 * Request permission approval from user
	 */
	private async requestPermissionApproval(
		serverName: string,
		toolName: string | undefined,
		type: PermissionType,
		scope: PermissionScope,
		reason: string,
		resourcePattern?: string,
	): Promise<boolean> {
		try {
			// Create permission request
			const request = this.permissionManager.createPermissionRequest(
				serverName,
				toolName,
				resourcePattern,
				type,
				scope,
				reason,
			)

			// Show approval dialog to user
			const approved = await this.showPermissionDialog(request)

			if (approved) {
				// Grant permission
				const permission = this.permissionManager.grantPermission(request.id)
				await this.permissionStore.savePermission(permission)

				await this.auditLogger.logPermissionGranted(
					serverName,
					toolName || "resource",
					permission.id,
					this.userContext.userId,
				)

				return true
			} else {
				await this.auditLogger.logPermissionDenied(
					serverName,
					toolName || "resource",
					"User denied permission request",
					this.userContext.userId,
				)

				return false
			}
		} catch (error) {
			console.error("Failed to request permission approval:", error)
			return false
		}
	}

	/**
	 * Show permission approval dialog to user
	 */
	private async showPermissionDialog(request: PermissionRequest): Promise<boolean> {
		const message =
			`Permission Request\n\n` +
			`Server: ${request.serverName}\n` +
			`${request.toolName ? `Tool: ${request.toolName}\n` : ""}` +
			`${request.resourcePattern ? `Resource: ${request.resourcePattern}\n` : ""}` +
			`Type: ${request.type}\n` +
			`Scope: ${request.requestedScope}\n` +
			`Reason: ${request.reason}\n\n` +
			`Risk Level: ${request.riskAssessment.level.toUpperCase()}\n` +
			`Risk Factors: ${request.riskAssessment.factors.join(", ")}\n\n` +
			`Do you want to grant this permission?`

		const choice = await vscode.window.showWarningMessage(message, { modal: true }, "Grant Permission", "Deny")

		return choice === "Grant Permission"
	}

	/**
	 * Get enhanced tools list with permission information
	 */
	async getEnhancedToolsList(serverName: string, source?: "global" | "project"): Promise<McpTool[]> {
		// Get connection and fetch tools directly since fetchToolsList is private
		const connection = this.connections.find(
			(conn) => conn.server.name === serverName && (source ? conn.server.source === source : true),
		)

		if (!connection) {
			return []
		}

		const tools = connection.server.tools || []

		// Enhance tools with permission information
		return tools.map((tool) => {
			const permissionResult = this.permissionManager.validatePermission(
				serverName,
				tool.name,
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
			)

			return {
				...tool,
				permissions: permissionResult.permission
					? {
							id: permissionResult.permission.id,
							scope: permissionResult.permission.scope,
							expiresAt: permissionResult.permission.expiresAt,
							usageCount: permissionResult.permission.usageCount,
							maxUsage: permissionResult.permission.quota?.maxExecutions,
							lastUsed: permissionResult.permission.lastUsedAt,
						}
					: undefined,
			}
		})
	}

	/**
	 * Revoke permission for a tool
	 */
	async revokeToolPermission(serverName: string, toolName: string, reason?: string): Promise<boolean> {
		try {
			const permissions = this.permissionManager.getPermissionsForServer(serverName)
			const toolPermissions = permissions.filter(
				(p) => p.toolName === toolName && p.status === PermissionStatus.ACTIVE,
			)

			let revokedCount = 0
			for (const permission of toolPermissions) {
				if (this.permissionManager.revokePermission(permission.id, reason)) {
					await this.permissionStore.savePermission(permission)
					revokedCount++
				}
			}

			if (revokedCount > 0) {
				await this.auditLogger.logEvent({
					type: AuditEventType.PERMISSION_REVOKED,
					severity: AuditSeverity.MEDIUM,
					serverName,
					toolName,
					userId: this.userContext.userId,
					success: true,
					message: `Revoked ${revokedCount} permissions for tool ${toolName}`,
					details: { reason, revokedCount },
				})
			}

			return revokedCount > 0
		} catch (error) {
			console.error("Failed to revoke tool permission:", error)
			return false
		}
	}

	/**
	 * Get permission statistics
	 */
	async getPermissionStatistics(): Promise<{
		totalPermissions: number
		activePermissions: number
		expiredPermissions: number
		revokedPermissions: number
		topServers: Array<{ serverName: string; permissionCount: number }>
		recentActivity: Array<{ timestamp: number; action: string; details: string }>
	}> {
		try {
			const storageStats = await this.permissionStore.getStatistics()
			const auditStats = await this.auditLogger.getStatistics({
				start: Date.now() - 7 * 24 * 60 * 60 * 1000, // Last 7 days
				end: Date.now(),
			})

			return {
				totalPermissions: storageStats.totalPermissions,
				activePermissions: storageStats.activePermissions,
				expiredPermissions: storageStats.expiredPermissions,
				revokedPermissions:
					storageStats.totalPermissions - storageStats.activePermissions - storageStats.expiredPermissions,
				topServers: auditStats.topServers.map((s) => ({ serverName: s.serverName, permissionCount: s.count })),
				recentActivity: auditStats.recentViolations.map((v) => ({
					timestamp: v.timestamp,
					action: v.type,
					details: v.message,
				})),
			}
		} catch (error) {
			console.error("Failed to get permission statistics:", error)
			return {
				totalPermissions: 0,
				activePermissions: 0,
				expiredPermissions: 0,
				revokedPermissions: 0,
				topServers: [],
				recentActivity: [],
			}
		}
	}

	/**
	 * Clean up expired permissions
	 */
	async cleanupExpiredPermissions(): Promise<number> {
		try {
			const cleanedPermissions = this.permissionManager.cleanupExpiredPermissions()
			const cleanedStorage = await this.permissionStore.cleanup()

			await this.auditLogger.logEvent({
				type: AuditEventType.SYSTEM_ERROR,
				severity: AuditSeverity.LOW,
				success: true,
				message: `Cleanup completed: ${cleanedPermissions} permissions expired, ${cleanedStorage.permissionsRemoved} removed from storage`,
				details: { cleanedPermissions, cleanedStorage },
			})

			return cleanedPermissions
		} catch (error) {
			console.error("Failed to cleanup expired permissions:", error)
			return 0
		}
	}

	/**
	 * Dispose enhanced components
	 */
	override async dispose(): Promise<void> {
		try {
			await this.permissionStore.dispose()
			await this.auditLogger.dispose()
			this.accessControlManager.cleanupExpiredSessions()
		} catch (error) {
			console.error("Failed to dispose enhanced components:", error)
		}

		await super.dispose()
	}
}
