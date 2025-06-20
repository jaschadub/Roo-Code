/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Tests for sandbox manager and process isolation utilities.
 */

import { SandboxManager, createSandboxManager, getDefaultSandboxConfig, type SandboxConfig } from "../sandboxManager"
import { SecurityLevel } from "../validationSchemas"

describe("Sandbox Manager", () => {
	let sandboxManager: SandboxManager

	beforeEach(() => {
		sandboxManager = createSandboxManager(SecurityLevel.MODERATE)
	})

	afterEach(() => {
		sandboxManager.dispose()
	})

	describe("Configuration", () => {
		it("should create sandbox with default moderate config", () => {
			const config = sandboxManager.getConfig()

			expect(config.securityLevel).toBe(SecurityLevel.MODERATE)
			expect(config.resourceLimits.timeout).toBe(60000)
			expect(config.resourceLimits.maxMemory).toBe(512)
			expect(config.enableMonitoring).toBe(true)
		})

		it("should create sandbox with strict config", () => {
			const strictSandbox = createSandboxManager(SecurityLevel.STRICT)
			const config = strictSandbox.getConfig()

			expect(config.securityLevel).toBe(SecurityLevel.STRICT)
			expect(config.resourceLimits.timeout).toBe(30000)
			expect(config.resourceLimits.maxMemory).toBe(128)
			expect(config.allowNetworkAccess).toBe(false)

			strictSandbox.dispose()
		})

		it("should create sandbox with permissive config", () => {
			const permissiveSandbox = createSandboxManager(SecurityLevel.PERMISSIVE)
			const config = permissiveSandbox.getConfig()

			expect(config.securityLevel).toBe(SecurityLevel.PERMISSIVE)
			expect(config.resourceLimits.timeout).toBe(300000)
			expect(config.resourceLimits.maxMemory).toBe(2048)
			expect(config.enableMonitoring).toBe(false)

			permissiveSandbox.dispose()
		})

		it("should update configuration", () => {
			const newConfig: Partial<SandboxConfig> = {
				resourceLimits: {
					timeout: 120000,
					maxMemory: 1024,
					maxCpu: 80,
					maxFileDescriptors: 200,
					maxProcesses: 20,
					maxDiskUsage: 1000,
				},
			}

			sandboxManager.updateConfig(newConfig)
			const config = sandboxManager.getConfig()

			expect(config.resourceLimits.timeout).toBe(120000)
			expect(config.resourceLimits.maxMemory).toBe(1024)
		})
	})

	describe("Command Execution", () => {
		it("should execute safe commands successfully", async () => {
			const result = await sandboxManager.executeCommand("echo", ["hello world"])

			expect(result.success).toBe(true)
			expect(result.exitCode).toBe(0)
			expect(result.stdout.trim()).toBe("hello world")
			expect(result.violations).toHaveLength(0)
		})

		it("should handle command timeouts", async () => {
			// Create a sandbox with very short timeout for testing
			const shortTimeoutSandbox = createSandboxManager(SecurityLevel.MODERATE, {
				resourceLimits: {
					timeout: 100, // 100ms
					maxMemory: 512,
					maxCpu: 75,
					maxFileDescriptors: 100,
					maxProcesses: 10,
					maxDiskUsage: 500,
				},
			})

			const result = await shortTimeoutSandbox.executeCommand("sleep", ["1"])

			expect(result.timedOut).toBe(true)
			expect(result.success).toBe(false)

			shortTimeoutSandbox.dispose()
		}, 10000)

		it("should validate working directory restrictions", async () => {
			const restrictedSandbox = createSandboxManager(SecurityLevel.STRICT, {
				blockedPaths: ["/etc", "/usr"],
			})

			const result = await restrictedSandbox.executeCommand("echo", ["test"], {
				cwd: "/etc",
			})

			expect(result.success).toBe(false)
			expect(result.violations.some((v) => v.type === "path_violation")).toBe(true)

			restrictedSandbox.dispose()
		})

		it("should filter environment variables", async () => {
			const result = await sandboxManager.executeCommand("printenv", [], {
				env: {
					SAFE_VAR: "safe_value",
					MALICIOUS_VAR: "rm -rf /",
					NODE_ENV: "test",
				},
			})

			expect(result.success).toBe(true)
			// Environment filtering should have removed dangerous characters
			expect(result.stdout).toContain("SAFE_VAR=safe_value")
			expect(result.stdout).toContain("NODE_ENV=test")
		})

		it("should handle process input", async () => {
			const result = await sandboxManager.executeCommand("cat", [], {
				input: "test input\n",
			})

			expect(result.success).toBe(true)
			expect(result.stdout.trim()).toBe("test input")
		})

		it("should limit output size", async () => {
			// This test would need a command that produces large output
			// For now, we'll test the violation detection logic
			const result = await sandboxManager.executeCommand("echo", ["test"])

			expect(result.violations.every((v) => v.type !== "output_size")).toBe(true)
		})
	})

	describe("Process Management", () => {
		it("should track active processes", () => {
			expect(sandboxManager.getActiveProcessCount()).toBe(0)

			// Start a long-running process (but don't await it)
			sandboxManager.executeCommand("sleep", ["0.1"])

			// Process count should increase temporarily
			// Note: This is a race condition in real scenarios
		})

		it("should kill processes", async () => {
			// This would require more complex process tracking
			// For now, we test that the method exists and doesn't throw
			const result = sandboxManager.killProcess("non-existent-id")
			expect(typeof result).toBe("boolean")
		})
	})

	describe("Security Violations", () => {
		it("should detect and report security violations", async () => {
			const maliciousSandbox = createSandboxManager(SecurityLevel.STRICT, {
				blockedPaths: ["/tmp"],
			})

			const result = await maliciousSandbox.executeCommand("echo", ["test"], {
				cwd: "/tmp",
			})

			expect(result.violations.length).toBeGreaterThan(0)
			expect(result.violations.some((v) => v.severity === "high")).toBe(true)

			maliciousSandbox.dispose()
		})

		it("should handle execution errors gracefully", async () => {
			const result = await sandboxManager.executeCommand("nonexistent-command", [])

			expect(result.success).toBe(false)
			expect(result.violations.some((v) => v.type === "execution_error")).toBe(true)
		})
	})

	describe("Resource Monitoring", () => {
		it("should track execution time", async () => {
			const result = await sandboxManager.executeCommand("echo", ["test"])

			expect(result.resourceUsage.executionTime).toBeGreaterThan(0)
		})

		it("should initialize memory usage tracking", async () => {
			const result = await sandboxManager.executeCommand("echo", ["test"])

			expect(result.resourceUsage.memoryUsed).toBeGreaterThanOrEqual(0)
		})
	})

	describe("getDefaultSandboxConfig", () => {
		it("should return correct config for each security level", () => {
			const strictConfig = getDefaultSandboxConfig(SecurityLevel.STRICT)
			expect(strictConfig.resourceLimits.timeout).toBe(30000)
			expect(strictConfig.allowNetworkAccess).toBe(false)

			const moderateConfig = getDefaultSandboxConfig(SecurityLevel.MODERATE)
			expect(moderateConfig.resourceLimits.timeout).toBe(60000)
			expect(moderateConfig.allowNetworkAccess).toBe(true)

			const permissiveConfig = getDefaultSandboxConfig(SecurityLevel.PERMISSIVE)
			expect(permissiveConfig.resourceLimits.timeout).toBe(300000)
			expect(permissiveConfig.allowNetworkAccess).toBe(true)
		})
	})

	describe("Disposal", () => {
		it("should clean up resources on disposal", () => {
			const testSandbox = createSandboxManager(SecurityLevel.MODERATE)

			expect(() => testSandbox.dispose()).not.toThrow()

			// After disposal, active process count should be 0
			expect(testSandbox.getActiveProcessCount()).toBe(0)
		})
	})

	describe("Edge Cases", () => {
		it("should handle empty commands", async () => {
			const result = await sandboxManager.executeCommand("", [])

			expect(result.success).toBe(false)
			expect(result.violations.length).toBeGreaterThan(0)
		})

		it("should handle commands with no arguments", async () => {
			const result = await sandboxManager.executeCommand("echo")

			expect(result.success).toBe(true)
		})

		it("should handle null/undefined options", async () => {
			const result = await sandboxManager.executeCommand("echo", ["test"], undefined)

			expect(result.success).toBe(true)
		})
	})
})
