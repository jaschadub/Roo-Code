/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Tests for the enhanced permission management system.
 */

import {
	PermissionManager,
	PermissionScope,
	PermissionType,
	PermissionStatus,
	DEFAULT_PERMISSION_POLICY,
} from "../permissionManager"

describe("PermissionManager", () => {
	let permissionManager: PermissionManager

	beforeEach(() => {
		permissionManager = new PermissionManager()
	})

	describe("Permission Request Creation", () => {
		test("should create a valid permission request", () => {
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission request",
			)

			expect(request.id).toBeDefined()
			expect(request.serverName).toBe("test-server")
			expect(request.toolName).toBe("test-tool")
			expect(request.type).toBe(PermissionType.TOOL_EXECUTION)
			expect(request.requestedScope).toBe(PermissionScope.EXECUTE)
			expect(request.reason).toBe("Test permission request")
			expect(request.riskAssessment).toBeDefined()
			expect(request.riskAssessment.level).toMatch(/^(low|medium|high)$/)
		})

		test("should assess risk correctly for different permission types", () => {
			const commandRequest = permissionManager.createPermissionRequest(
				"test-server",
				"dangerous-command",
				undefined,
				PermissionType.COMMAND_EXECUTION,
				PermissionScope.FULL_ACCESS,
				"Execute system commands",
			)

			const resourceRequest = permissionManager.createPermissionRequest(
				"test-server",
				undefined,
				"file://test.txt",
				PermissionType.RESOURCE_ACCESS,
				PermissionScope.READ_ONLY,
				"Read test file",
			)

			expect(commandRequest.riskAssessment.level).toBe("high")
			expect(resourceRequest.riskAssessment.level).toBe("low")
		})
	})

	describe("Permission Granting", () => {
		test("should grant permission from valid request", () => {
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission",
			)

			const permission = permissionManager.grantPermission(request.id)

			expect(permission.id).toBeDefined()
			expect(permission.serverName).toBe("test-server")
			expect(permission.toolName).toBe("test-tool")
			expect(permission.status).toBe(PermissionStatus.ACTIVE)
			expect(permission.userApproved).toBe(true)
			expect(permission.grantedAt).toBeDefined()
			expect(permission.expiresAt).toBeDefined()
			expect(permission.auditTrail).toHaveLength(1)
		})

		test("should throw error for invalid request ID", () => {
			expect(() => {
				permissionManager.grantPermission("invalid-id")
			}).toThrow("Permission request invalid-id not found")
		})

		test("should apply custom scope and duration", () => {
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.FULL_ACCESS,
				"Test permission",
			)

			const customDuration = 60 * 60 * 1000 // 1 hour
			const permission = permissionManager.grantPermission(request.id, PermissionScope.READ_ONLY, customDuration)

			expect(permission.scope).toBe(PermissionScope.READ_ONLY)
			expect(permission.expiresAt).toBe(permission.grantedAt + customDuration)
		})
	})

	describe("Permission Validation", () => {
		test("should validate active permission successfully", () => {
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission",
			)

			permissionManager.grantPermission(request.id)

			const result = permissionManager.validatePermission(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
			)

			expect(result.allowed).toBe(true)
			expect(result.permission).toBeDefined()
			expect(result.reason).toBe("Permission validated successfully")
		})

		test("should deny permission for non-existent permission", () => {
			const result = permissionManager.validatePermission(
				"non-existent-server",
				"non-existent-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
			)

			expect(result.allowed).toBe(false)
			expect(result.reason).toBe("No matching permission found")
			expect(result.violations).toContain("No permission exists for this action")
		})

		test("should deny permission for insufficient scope", () => {
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.READ_ONLY,
				"Test permission",
			)

			permissionManager.grantPermission(request.id, PermissionScope.READ_ONLY)

			const result = permissionManager.validatePermission(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.ADMIN,
			)

			expect(result.allowed).toBe(false)
			expect(result.reason).toBe("Insufficient permission scope")
		})

		test("should handle expired permissions", () => {
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission",
			)

			// Grant permission that expires immediately
			const permission = permissionManager.grantPermission(request.id, undefined, 1)

			// Wait for expiration
			setTimeout(() => {
				const result = permissionManager.validatePermission(
					"test-server",
					"test-tool",
					undefined,
					PermissionType.TOOL_EXECUTION,
					PermissionScope.EXECUTE,
				)

				expect(result.allowed).toBe(false)
				expect(result.reason).toBe("All matching permissions have expired")
				expect(permission.status).toBe(PermissionStatus.EXPIRED)
			}, 10)
		})
	})

	describe("Permission Usage Tracking", () => {
		test("should record permission usage", () => {
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission",
			)

			const permission = permissionManager.grantPermission(request.id)
			const initialUsageCount = permission.usageCount

			permissionManager.recordUsage(permission.id, { testContext: "test" })

			expect(permission.usageCount).toBe(initialUsageCount + 1)
			expect(permission.lastUsedAt).toBeDefined()
			expect(permission.auditTrail).toHaveLength(2) // Grant + Usage
		})

		test("should handle usage recording for non-existent permission", () => {
			// Should not throw error
			expect(() => {
				permissionManager.recordUsage("non-existent-id")
			}).not.toThrow()
		})
	})

	describe("Permission Revocation", () => {
		test("should revoke active permission", () => {
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"test-tool",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission",
			)

			const permission = permissionManager.grantPermission(request.id)
			const revoked = permissionManager.revokePermission(permission.id, "Test revocation")

			expect(revoked).toBe(true)
			expect(permission.status).toBe(PermissionStatus.REVOKED)
			expect(permission.auditTrail).toHaveLength(2) // Grant + Revoke
		})

		test("should return false for non-existent permission", () => {
			const revoked = permissionManager.revokePermission("non-existent-id")
			expect(revoked).toBe(false)
		})
	})

	describe("Permission Cleanup", () => {
		test("should clean up expired permissions", () => {
			// Create permissions with different expiration times
			const request1 = permissionManager.createPermissionRequest(
				"test-server",
				"tool1",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission 1",
			)

			const request2 = permissionManager.createPermissionRequest(
				"test-server",
				"tool2",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission 2",
			)

			// Grant one that expires immediately, one that doesn't
			const expiredPermission = permissionManager.grantPermission(request1.id, undefined, 1)
			const activePermission = permissionManager.grantPermission(request2.id, undefined, 60000)

			// Wait for expiration
			setTimeout(() => {
				const cleanedCount = permissionManager.cleanupExpiredPermissions()

				expect(cleanedCount).toBe(1)
				expect(expiredPermission.status).toBe(PermissionStatus.EXPIRED)
				expect(activePermission.status).toBe(PermissionStatus.ACTIVE)
			}, 10)
		})
	})

	describe("Server Permissions", () => {
		test("should get all permissions for a server", () => {
			const request1 = permissionManager.createPermissionRequest(
				"test-server",
				"tool1",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission 1",
			)

			const request2 = permissionManager.createPermissionRequest(
				"test-server",
				"tool2",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission 2",
			)

			const request3 = permissionManager.createPermissionRequest(
				"other-server",
				"tool3",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission 3",
			)

			permissionManager.grantPermission(request1.id)
			permissionManager.grantPermission(request2.id)
			permissionManager.grantPermission(request3.id)

			const serverPermissions = permissionManager.getPermissionsForServer("test-server")

			expect(serverPermissions).toHaveLength(2)
			expect(serverPermissions.every((p) => p.serverName === "test-server")).toBe(true)
		})
	})

	describe("Pending Requests", () => {
		test("should get pending requests", () => {
			const request1 = permissionManager.createPermissionRequest(
				"test-server",
				"tool1",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission 1",
			)

			const request2 = permissionManager.createPermissionRequest(
				"test-server",
				"tool2",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission 2",
			)

			// Grant one request, leave one pending
			permissionManager.grantPermission(request1.id)

			const pendingRequests = permissionManager.getPendingRequests()

			expect(pendingRequests).toHaveLength(1)
			expect(pendingRequests[0].id).toBe(request2.id)
		})

		test("should clean up expired requests", () => {
			// Create request that expires immediately
			const request = permissionManager.createPermissionRequest(
				"test-server",
				"tool1",
				undefined,
				PermissionType.TOOL_EXECUTION,
				PermissionScope.EXECUTE,
				"Test permission",
			)

			// Manually set expiration to past
			const pendingRequests = permissionManager.getPendingRequests()
			const pendingRequest = pendingRequests.find((r) => r.id === request.id)
			if (pendingRequest) {
				pendingRequest.expiresAt = Date.now() - 1000
			}

			// Get pending requests again - should clean up expired
			const remainingRequests = permissionManager.getPendingRequests()

			expect(remainingRequests).toHaveLength(0)
		})
	})
})
