/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 */
import {
	SecurityManager,
	getSecurityManager,
	processValidationResult,
	createSecurityErrorMessage,
	validateServerName,
	validateToolName,
	sanitizeErrorMessage,
	isSecurityViolation,
	isValidationError,
	DEFAULT_SECURITY_POLICY,
} from "../securityUtils"
import { SecurityLevel, type ValidationResult, type ValidationContext } from "../validationSchemas"
import { SecurityValidationError } from "../inputSanitizer"
import { z } from "zod"

describe("securityUtils", () => {
	describe("SecurityManager", () => {
		let securityManager: SecurityManager

		beforeEach(() => {
			securityManager = new SecurityManager()
		})

		afterEach(() => {
			securityManager.reset()
		})

		it("should initialize with default policy", () => {
			const policy = securityManager.getPolicy()
			expect(policy.defaultSecurityLevel).toBe(DEFAULT_SECURITY_POLICY.defaultSecurityLevel)
			expect(policy.logSecurityViolations).toBe(DEFAULT_SECURITY_POLICY.logSecurityViolations)
		})

		it("should update policy", () => {
			securityManager.updatePolicy({
				defaultSecurityLevel: SecurityLevel.STRICT,
				maxViolationsPerServer: 10,
			})

			const policy = securityManager.getPolicy()
			expect(policy.defaultSecurityLevel).toBe(SecurityLevel.STRICT)
			expect(policy.maxViolationsPerServer).toBe(10)
		})

		it("should get security level for server", () => {
			securityManager.updatePolicy({
				defaultSecurityLevel: SecurityLevel.MODERATE,
				serverSpecificRules: {
					"trusted-server": { defaultSecurityLevel: SecurityLevel.PERMISSIVE },
					"untrusted-server": { defaultSecurityLevel: SecurityLevel.STRICT },
				},
			})

			expect(securityManager.getSecurityLevelForServer("trusted-server")).toBe(SecurityLevel.PERMISSIVE)
			expect(securityManager.getSecurityLevelForServer("untrusted-server")).toBe(SecurityLevel.STRICT)
			expect(securityManager.getSecurityLevelForServer("unknown-server")).toBe(SecurityLevel.MODERATE)
		})

		it("should record violations", () => {
			const context: ValidationContext = {
				securityLevel: SecurityLevel.MODERATE,
				timestamp: Date.now(),
			}

			const record = securityManager.recordViolation(
				"test-server",
				"test-field",
				"test violation",
				"medium",
				context,
				"test-tool",
			)

			expect(record.serverName).toBe("test-server")
			expect(record.field).toBe("test-field")
			expect(record.violation).toBe("test violation")
			expect(record.severity).toBe("medium")
			expect(record.toolName).toBe("test-tool")
			expect(record.id).toBeDefined()
		})

		it("should track metrics", () => {
			const context: ValidationContext = {
				securityLevel: SecurityLevel.MODERATE,
				timestamp: Date.now(),
			}

			securityManager.recordValidation()
			securityManager.recordValidation()
			securityManager.recordViolation("server1", "field1", "violation1", "low", context)
			securityManager.recordViolation("server2", "field2", "violation2", "high", context)

			const metrics = securityManager.getMetrics()
			expect(metrics.totalValidations).toBe(2)
			expect(metrics.totalViolations).toBe(2)
			expect(metrics.violationsByServer["server1"]).toBe(1)
			expect(metrics.violationsByServer["server2"]).toBe(1)
			expect(metrics.violationsBySeverity.low).toBe(1)
			expect(metrics.violationsBySeverity.high).toBe(1)
		})

		it("should block servers with too many violations", () => {
			securityManager.updatePolicy({
				maxViolationsPerServer: 2,
				blockOnViolations: true,
			})

			const context: ValidationContext = {
				securityLevel: SecurityLevel.MODERATE,
				timestamp: Date.now(),
			}

			// Record violations below threshold
			securityManager.recordViolation("test-server", "field1", "violation1", "low", context)
			expect(securityManager.shouldBlockServer("test-server")).toBe(false)

			// Record violation that reaches threshold
			securityManager.recordViolation("test-server", "field2", "violation2", "medium", context)
			expect(securityManager.shouldBlockServer("test-server")).toBe(true)
		})

		it("should not block when blocking is disabled", () => {
			securityManager.updatePolicy({
				maxViolationsPerServer: 1,
				blockOnViolations: false,
			})

			const context: ValidationContext = {
				securityLevel: SecurityLevel.MODERATE,
				timestamp: Date.now(),
			}

			securityManager.recordViolation("test-server", "field1", "violation1", "high", context)
			expect(securityManager.shouldBlockServer("test-server")).toBe(false)
		})

		it("should get violation history", () => {
			const context: ValidationContext = {
				securityLevel: SecurityLevel.MODERATE,
				timestamp: Date.now(),
			}

			securityManager.recordViolation("server1", "field1", "violation1", "low", context)
			securityManager.recordViolation("server1", "field2", "violation2", "medium", context)
			securityManager.recordViolation("server2", "field3", "violation3", "high", context)

			const history = securityManager.getViolationHistory("server1")
			expect(history).toHaveLength(2)
			expect(history[0].serverName).toBe("server1")
			expect(history[1].serverName).toBe("server1")
		})

		it("should reset metrics and violations", () => {
			const context: ValidationContext = {
				securityLevel: SecurityLevel.MODERATE,
				timestamp: Date.now(),
			}

			securityManager.recordValidation()
			securityManager.recordViolation("test-server", "field1", "violation1", "low", context)

			let metrics = securityManager.getMetrics()
			expect(metrics.totalValidations).toBe(1)
			expect(metrics.totalViolations).toBe(1)

			securityManager.reset()

			metrics = securityManager.getMetrics()
			expect(metrics.totalValidations).toBe(0)
			expect(metrics.totalViolations).toBe(0)
		})
	})

	describe("getSecurityManager", () => {
		it("should return singleton instance", () => {
			const manager1 = getSecurityManager()
			const manager2 = getSecurityManager()
			expect(manager1).toBe(manager2)
		})

		it("should update policy on existing instance", () => {
			const manager = getSecurityManager({ defaultSecurityLevel: SecurityLevel.STRICT })
			expect(manager.getPolicy().defaultSecurityLevel).toBe(SecurityLevel.STRICT)

			getSecurityManager({ maxViolationsPerServer: 10 })
			expect(manager.getPolicy().maxViolationsPerServer).toBe(10)
		})
	})

	describe("processValidationResult", () => {
		it("should process successful validation", () => {
			const result: ValidationResult<any> = {
				success: true,
				data: { test: "data" },
				context: {
					securityLevel: SecurityLevel.MODERATE,
					timestamp: Date.now(),
				},
			}

			const processed = processValidationResult(result, "test-server", "test-tool")
			expect(processed.success).toBe(true)
			expect(processed.data).toEqual({ test: "data" })
		})

		it("should process failed validation with security violations", () => {
			const result: ValidationResult<any> = {
				success: false,
				securityViolations: [{ field: "test-field", violation: "test violation", severity: "medium" }],
				context: {
					securityLevel: SecurityLevel.MODERATE,
					timestamp: Date.now(),
				},
			}

			const processed = processValidationResult(result, "test-server", "test-tool")
			expect(processed.success).toBe(false)
			expect(processed.securityViolations).toBeDefined()
		})

		it("should block execution for high severity violations", () => {
			const result: ValidationResult<any> = {
				success: false,
				securityViolations: [{ field: "test-field", violation: "critical violation", severity: "high" }],
				context: {
					securityLevel: SecurityLevel.MODERATE,
					timestamp: Date.now(),
				},
			}

			const processed = processValidationResult(result, "test-server", "test-tool")
			expect(processed.success).toBe(false)
			expect(processed.securityViolations?.some((v) => v.violation.includes("blocked"))).toBe(true)
		})
	})

	describe("createSecurityErrorMessage", () => {
		it("should create message for high severity violations", () => {
			const violations = [
				{ field: "test-field", violation: "critical error", severity: "high" },
				{ field: "other-field", violation: "minor error", severity: "low" },
			]

			const message = createSecurityErrorMessage(violations, "test-server")
			expect(message).toContain("Security violation detected in test-server")
			expect(message).toContain("critical error")
			expect(message).toContain("Execution blocked")
		})

		it("should create summary for multiple low/medium violations", () => {
			const violations = [
				{ field: "field1", violation: "error1", severity: "medium" },
				{ field: "field2", violation: "error2", severity: "low" },
			]

			const message = createSecurityErrorMessage(violations, "test-server")
			expect(message).toContain("Security violations detected in test-server")
			expect(message).toContain("field1: error1")
			expect(message).toContain("field2: error2")
		})
	})

	describe("validateServerName", () => {
		it("should validate safe server names", () => {
			const validNames = ["test-server", "server_name", "server.example", "server123"]

			validNames.forEach((name) => {
				expect(validateServerName(name)).toBe(true)
			})
		})

		it("should reject unsafe server names", () => {
			const invalidNames = [
				"server with spaces",
				"server@domain",
				"server/path",
				"server;command",
				"a".repeat(101), // too long
			]

			invalidNames.forEach((name) => {
				expect(validateServerName(name)).toBe(false)
			})
		})
	})

	describe("validateToolName", () => {
		it("should validate safe tool names", () => {
			const validNames = ["test-tool", "tool_name", "tool.action", "tool123"]

			validNames.forEach((name) => {
				expect(validateToolName(name)).toBe(true)
			})
		})

		it("should reject unsafe tool names", () => {
			const invalidNames = [
				"tool with spaces",
				"tool@action",
				"tool/action",
				"tool;command",
				"a".repeat(101), // too long
			]

			invalidNames.forEach((name) => {
				expect(validateToolName(name)).toBe(false)
			})
		})
	})

	describe("sanitizeErrorMessage", () => {
		it("should sanitize SecurityValidationError", () => {
			const error = new SecurityValidationError("Test error", "test-field", "sensitive-value", "test_violation")

			const sanitized = sanitizeErrorMessage(error)
			expect(sanitized).toContain("test-field")
			expect(sanitized).toContain("test_violation")
			expect(sanitized).not.toContain("sensitive-value")
		})

		it("should sanitize ZodError", () => {
			const zodError = new z.ZodError([
				{
					code: z.ZodIssueCode.invalid_type,
					expected: "string",
					received: "number",
					path: ["field1"],
					message: "Expected string, received number",
				},
				{
					code: z.ZodIssueCode.too_small,
					minimum: 1,
					type: "string",
					inclusive: true,
					path: ["field2"],
					message: "String must contain at least 1 character(s)",
				},
			])

			const sanitized = sanitizeErrorMessage(zodError)
			expect(sanitized).toContain("field1: Expected string, received number")
			expect(sanitized).toContain("field2: String must contain at least 1 character(s)")
		})

		it("should sanitize generic Error", () => {
			const error = new Error("Test error with <script>alert('xss')</script>")
			const sanitized = sanitizeErrorMessage(error)
			expect(sanitized).toBe("Test error with scriptalert(xss)/script")
		})

		it("should handle unknown errors", () => {
			const sanitized = sanitizeErrorMessage("unknown error")
			expect(sanitized).toBe("Unknown validation error")
		})
	})

	describe("type guards", () => {
		it("should identify SecurityValidationError", () => {
			const securityError = new SecurityValidationError("test", "field", "value", "type")
			const regularError = new Error("test")

			expect(isSecurityViolation(securityError)).toBe(true)
			expect(isSecurityViolation(regularError)).toBe(false)
		})

		it("should identify ZodError", () => {
			const zodError = new z.ZodError([])
			const regularError = new Error("test")

			expect(isValidationError(zodError)).toBe(true)
			expect(isValidationError(regularError)).toBe(false)
		})
	})

	describe("DEFAULT_SECURITY_POLICY", () => {
		it("should have expected default values", () => {
			expect(DEFAULT_SECURITY_POLICY.defaultSecurityLevel).toBe(SecurityLevel.MODERATE)
			expect(DEFAULT_SECURITY_POLICY.logSecurityViolations).toBe(true)
			expect(DEFAULT_SECURITY_POLICY.blockOnViolations).toBe(true)
			expect(DEFAULT_SECURITY_POLICY.maxViolationsPerServer).toBe(5)
			expect(DEFAULT_SECURITY_POLICY.violationTimeWindow).toBe(300000) // 5 minutes
		})
	})
})
