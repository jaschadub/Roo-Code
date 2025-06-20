/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Tests for the role-based access control system.
 */

import { AccessControlManager, UserRole, DEFAULT_ACCESS_CONTROL_POLICY } from "../accessControl"
import { PermissionManager, PermissionType, PermissionScope } from "../permissionManager"

describe("AccessControlManager", () => {
	let accessControlManager: AccessControlManager
	let permissionManager: PermissionManager

	beforeEach(() => {
		permissionManager = new PermissionManager()
		accessControlManager = new AccessControlManager(permissionManager)
	})

	describe("User Context Management", () => {
		test("should create user context with default role", () => {
			const context = accessControlManager.createUserContext()

			expect(context.role).toBe(DEFAULT_ACCESS_CONTROL_POLICY.defaultRole)
			expect(context.isAuthenticated).toBe(!DEFAULT_ACCESS_CONTROL_POLICY.requireAuthentication)
			expect(context.lastActivity).toBeDefined()
		})

		test("should create user context with custom role", () => {
			const context = accessControlManager.createUserContext(UserRole.ADMIN, {
				userId: "test-user",
				sessionId: "test-session",
			})

			expect(context.role).toBe(UserRole.ADMIN)
			expect(context.userId).toBe("test-user")
			expect(context.sessionId).toBe("test-session")
		})

		test("should store and retrieve user context by session", () => {
			const context = accessControlManager.createUserContext(UserRole.USER, {
				sessionId: "test-session",
			})

			const retrievedContext = accessControlManager.getUserContext("test-session")

			expect(retrievedContext).toBeDefined()
			expect(retrievedContext?.role).toBe(UserRole.USER)
			expect(retrievedContext?.sessionId).toBe("test-session")
		})

		test("should return undefined for non-existent session", () => {
			const context = accessControlManager.getUserContext("non-existent")
			expect(context).toBeUndefined()
		})
	})

	describe("Role Capabilities", () => {
		test("should get correct capabilities for guest role", () => {
			const capabilities = accessControlManager.getRoleCapabilities(UserRole.GUEST)

			expect(capabilities.canExecuteTools).toBe(false)
			expect(capabilities.canAccessResources).toBe(true)
			expect(capabilities.canModifyFiles).toBe(false)
			expect(capabilities.canExecuteCommands).toBe(false)
			expect(capabilities.allowedScopes).toContain(PermissionScope.READ_ONLY)
			expect(capabilities.allowedTypes).toContain(PermissionType.RESOURCE_ACCESS)
		})

		test("should get correct capabilities for user role", () => {
			const capabilities = accessControlManager.getRoleCapabilities(UserRole.USER)

			expect(capabilities.canExecuteTools).toBe(true)
			expect(capabilities.canAccessResources).toBe(true)
			expect(capabilities.canModifyFiles).toBe(false)
			expect(capabilities.canExecuteCommands).toBe(false)
			expect(capabilities.allowedScopes).toContain(PermissionScope.EXECUTE)
			expect(capabilities.allowedTypes).toContain(PermissionType.TOOL_EXECUTION)
		})

		test("should get correct capabilities for developer role", () => {
			const capabilities = accessControlManager.getRoleCapabilities(UserRole.DEVELOPER)

			expect(capabilities.canExecuteTools).toBe(true)
			expect(capabilities.canAccessResources).toBe(true)
			expect(capabilities.canModifyFiles).toBe(true)
			expect(capabilities.canExecuteCommands).toBe(true)
			expect(capabilities.canAccessNetwork).toBe(true)
			expect(capabilities.allowedScopes).toContain(PermissionScope.ADMIN)
			expect(capabilities.allowedTypes).toContain(PermissionType.COMMAND_EXECUTION)
		})

		test("should get correct capabilities for admin role", () => {
			const capabilities = accessControlManager.getRoleCapabilities(UserRole.ADMIN)

			expect(capabilities.canManagePermissions).toBe(true)
			expect(capabilities.canDelegatePermissions).toBe(true)
			expect(capabilities.canViewAuditLogs).toBe(true)
			expect(capabilities.allowedScopes).toContain(PermissionScope.FULL_ACCESS)
		})

		test("should inherit capabilities from lower roles", () => {
			const adminCapabilities = accessControlManager.getRoleCapabilities(UserRole.ADMIN)
			const userCapabilities = accessControlManager.getRoleCapabilities(UserRole.USER)

			// Admin should have all user capabilities plus more
			expect(adminCapabilities.canExecuteTools).toBe(true)
			expect(adminCapabilities.canAccessResources).toBe(true)
			expect(adminCapabilities.allowedTypes).toEqual(expect.arrayContaining(userCapabilities.allowedTypes))
		})
	})

	describe("Access Control Checks", () => {
		test("should allow tool execution for user role", () => {
			const context = accessControlManager.createUserContext(UserRole.USER)

			const result = accessControlManager.checkAccess(context, {
				type: PermissionType.TOOL_EXECUTION,
				scope: PermissionScope.EXECUTE,
				serverName: "test-server",
				toolName: "test-tool",
			})

			expect(result.allowed).toBe(true)
			expect(result.role).toBe(UserRole.USER)
		})

		test("should deny command execution for user role", () => {
			const context = accessControlManager.createUserContext(UserRole.USER)

			const result = accessControlManager.checkAccess(context, {
				type: PermissionType.COMMAND_EXECUTION,
				scope: PermissionScope.EXECUTE,
				serverName: "test-server",
			})

			expect(result.allowed).toBe(false)
			expect(result.reason).toContain("not allowed to perform")
			expect(result.restrictions).toContain("Permission type command_execution not allowed for role user")
		})

		test("should allow command execution for developer role", () => {
			const context = accessControlManager.createUserContext(UserRole.DEVELOPER)

			const result = accessControlManager.checkAccess(context, {
				type: PermissionType.COMMAND_EXECUTION,
				scope: PermissionScope.EXECUTE,
				serverName: "test-server",
			})

			expect(result.allowed).toBe(true)
			expect(result.role).toBe(UserRole.DEVELOPER)
		})

		test("should deny full access scope for user role", () => {
			const context = accessControlManager.createUserContext(UserRole.USER)

			const result = accessControlManager.checkAccess(context, {
				type: PermissionType.TOOL_EXECUTION,
				scope: PermissionScope.FULL_ACCESS,
				serverName: "test-server",
			})

			expect(result.allowed).toBe(false)
			expect(result.reason).toContain("not allowed scope")
		})

		test("should require authentication when policy requires it", () => {
			// Update policy to require authentication
			accessControlManager.updatePolicy({ requireAuthentication: true })

			const context = accessControlManager.createUserContext(UserRole.USER, {
				isAuthenticated: false,
			})

			const result = accessControlManager.checkAccess(context, {
				type: PermissionType.TOOL_EXECUTION,
				scope: PermissionScope.EXECUTE,
				serverName: "test-server",
			})

			expect(result.allowed).toBe(false)
			expect(result.reason).toBe("Authentication required")
		})
	})

	describe("Role Elevation", () => {
		test("should allow role elevation for users with delegation capability", () => {
			const context = accessControlManager.createUserContext(UserRole.DEVELOPER)

			const elevated = accessControlManager.elevateRole(
				context,
				UserRole.ADMIN,
				60000, // 1 minute
				"Temporary admin access for testing",
			)

			expect(elevated).toBe(true)
			expect(context.role).toBe(UserRole.ADMIN)
		})

		test("should deny role elevation for users without delegation capability", () => {
			const context = accessControlManager.createUserContext(UserRole.USER)

			const elevated = accessControlManager.elevateRole(
				context,
				UserRole.ADMIN,
				60000,
				"Unauthorized elevation attempt",
			)

			expect(elevated).toBe(false)
			expect(context.role).toBe(UserRole.USER) // Should remain unchanged
		})

		test("should deny elevation to lower or same role", () => {
			const context = accessControlManager.createUserContext(UserRole.DEVELOPER)

			const elevated = accessControlManager.elevateRole(
				context,
				UserRole.USER,
				60000,
				"Invalid elevation attempt",
			)

			expect(elevated).toBe(false)
			expect(context.role).toBe(UserRole.DEVELOPER)
		})

		test("should deny elevation beyond reasonable limits", () => {
			const context = accessControlManager.createUserContext(UserRole.USER)

			const elevated = accessControlManager.elevateRole(
				context,
				UserRole.SUPER_ADMIN,
				60000,
				"Excessive elevation attempt",
			)

			expect(elevated).toBe(false)
			expect(context.role).toBe(UserRole.USER)
		})
	})

	describe("Session Management", () => {
		test("should track active sessions", () => {
			accessControlManager.createUserContext(UserRole.USER, { sessionId: "session1" })
			accessControlManager.createUserContext(UserRole.DEVELOPER, { sessionId: "session2" })

			const count = accessControlManager.getActiveSessionsCount()
			expect(count).toBe(2)
		})

		test("should clean up expired sessions", () => {
			// Create session with very short timeout
			accessControlManager.updatePolicy({ sessionTimeout: 1 })

			const context = accessControlManager.createUserContext(UserRole.USER, {
				sessionId: "short-session",
			})

			// Wait for session to expire
			setTimeout(() => {
				const cleanedCount = accessControlManager.cleanupExpiredSessions()
				expect(cleanedCount).toBe(1)

				const retrievedContext = accessControlManager.getUserContext("short-session")
				expect(retrievedContext).toBeUndefined()
			}, 10)
		})

		test("should revoke specific sessions", () => {
			accessControlManager.createUserContext(UserRole.USER, { sessionId: "revoke-me" })

			const revoked = accessControlManager.revokeSession("revoke-me")
			expect(revoked).toBe(true)

			const context = accessControlManager.getUserContext("revoke-me")
			expect(context).toBeUndefined()
		})

		test("should enforce maximum concurrent sessions", () => {
			accessControlManager.updatePolicy({ maxConcurrentSessions: 2 })

			accessControlManager.createUserContext(UserRole.USER, { sessionId: "session1" })
			accessControlManager.createUserContext(UserRole.USER, { sessionId: "session2" })

			const canCreate = accessControlManager.canCreateSession()
			expect(canCreate).toBe(false)
		})
	})

	describe("Audit Access", () => {
		test("should allow audit log access for admin roles", () => {
			const adminContext = accessControlManager.createUserContext(UserRole.ADMIN)
			accessControlManager.createUserContext(UserRole.USER, { sessionId: "user-session" })

			const sessions = accessControlManager.getActiveSessions(adminContext)
			expect(sessions.length).toBeGreaterThan(0)
		})

		test("should deny audit log access for non-admin roles", () => {
			const userContext = accessControlManager.createUserContext(UserRole.USER)
			accessControlManager.createUserContext(UserRole.ADMIN, { sessionId: "admin-session" })

			const sessions = accessControlManager.getActiveSessions(userContext)
			expect(sessions).toHaveLength(0)
		})
	})

	describe("Policy Management", () => {
		test("should update policy settings", () => {
			const newPolicy = {
				defaultRole: UserRole.DEVELOPER,
				requireAuthentication: true,
				sessionTimeout: 30000,
			}

			accessControlManager.updatePolicy(newPolicy)
			const currentPolicy = accessControlManager.getPolicy()

			expect(currentPolicy.defaultRole).toBe(UserRole.DEVELOPER)
			expect(currentPolicy.requireAuthentication).toBe(true)
			expect(currentPolicy.sessionTimeout).toBe(30000)
		})

		test("should preserve existing policy settings when partially updating", () => {
			const originalPolicy = accessControlManager.getPolicy()

			accessControlManager.updatePolicy({ defaultRole: UserRole.DEVELOPER })
			const updatedPolicy = accessControlManager.getPolicy()

			expect(updatedPolicy.defaultRole).toBe(UserRole.DEVELOPER)
			expect(updatedPolicy.requireAuthentication).toBe(originalPolicy.requireAuthentication)
			expect(updatedPolicy.sessionTimeout).toBe(originalPolicy.sessionTimeout)
		})
	})

	describe("Session Timeout Handling", () => {
		test("should update last activity when accessing session", () => {
			const context = accessControlManager.createUserContext(UserRole.USER, {
				sessionId: "activity-test",
			})
			const initialActivity = context.lastActivity

			// Wait a bit then access session
			setTimeout(() => {
				const retrievedContext = accessControlManager.getUserContext("activity-test")
				expect(retrievedContext?.lastActivity).toBeGreaterThan(initialActivity)
			}, 10)
		})

		test("should handle session timeout correctly", () => {
			// Set very short timeout
			accessControlManager.updatePolicy({ sessionTimeout: 1 })

			accessControlManager.createUserContext(UserRole.USER, {
				sessionId: "timeout-test",
			})

			// Wait for timeout then try to access
			setTimeout(() => {
				const context = accessControlManager.getUserContext("timeout-test")
				expect(context).toBeUndefined()
			}, 10)
		})
	})
})
