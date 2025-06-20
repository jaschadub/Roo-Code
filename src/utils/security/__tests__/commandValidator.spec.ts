/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Tests for command validation and security utilities.
 */

import {
	validateCommand,
	validateWorkingDirectory,
	createSecureCommandWrapper,
	CommandValidationError,
	getDefaultCommandConfig,
	type CommandValidationConfig,
} from "../commandValidator"
import { SecurityLevel } from "../validationSchemas"

describe("Command Validator", () => {
	describe("validateCommand", () => {
		it("should validate safe commands in moderate security level", () => {
			const result = validateCommand("node", ["index.js"], undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(true)
			expect(result.sanitizedCommand).toBe("node")
			expect(result.sanitizedArgs).toEqual(["index.js"])
			expect(result.violations).toHaveLength(0)
		})

		it("should block dangerous commands in strict security level", () => {
			const result = validateCommand("rm", ["-rf", "/"], undefined, SecurityLevel.STRICT)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.severity === "high")).toBe(true)
			expect(result.violations.some((v) => v.type === "command_not_allowed")).toBe(true)
		})

		it("should detect shell metacharacters", () => {
			const result = validateCommand("node", ["index.js; rm -rf /"], undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "blocked_pattern")).toBe(true)
		})

		it("should validate command length limits", () => {
			const longCommand = "a".repeat(2000)
			const result = validateCommand(longCommand, [], undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "command_length")).toBe(true)
		})

		it("should validate argument count limits", () => {
			const manyArgs = Array(200).fill("arg")
			const result = validateCommand("node", manyArgs, undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "argument_count")).toBe(true)
		})

		it("should allow all commands in permissive mode", () => {
			const result = validateCommand("rm", ["-rf", "/tmp/test"], undefined, SecurityLevel.PERMISSIVE)

			expect(result.isValid).toBe(true)
		})

		it("should validate path traversal in arguments", () => {
			const result = validateCommand("node", ["../../../etc/passwd"], undefined, SecurityLevel.STRICT)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "path_traversal")).toBe(true)
		})

		it("should validate executable extensions", () => {
			const config: Partial<CommandValidationConfig> = {
				allowedExecutableExtensions: [".js"],
			}
			const result = validateCommand("node", ["script.exe"], config, SecurityLevel.STRICT)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "executable_extension")).toBe(true)
		})
	})

	describe("validateWorkingDirectory", () => {
		it("should validate safe working directories", () => {
			const result = validateWorkingDirectory("/home/user/project", ["/home/user"], SecurityLevel.MODERATE)

			expect(result.isValid).toBe(true)
			expect(result.violations).toHaveLength(0)
		})

		it("should block path traversal in working directory", () => {
			const result = validateWorkingDirectory("/home/user/../../../etc", [], SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "path_traversal")).toBe(true)
		})

		it("should validate allowed directories", () => {
			const result = validateWorkingDirectory("/tmp/malicious", ["/home/user"], SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "directory_not_allowed")).toBe(true)
		})
	})

	describe("createSecureCommandWrapper", () => {
		it("should create secure wrapper for valid commands", () => {
			const wrapper = createSecureCommandWrapper("node", ["index.js"], {
				cwd: "/home/user/project",
				timeout: 30000,
				securityLevel: SecurityLevel.MODERATE,
			})

			expect(wrapper.command).toBe("node")
			expect(wrapper.args).toEqual(["index.js"])
			expect(wrapper.options.cwd).toBe("/home/user/project")
			expect(wrapper.options.timeout).toBe(30000)
			expect(wrapper.options.shell).toBe(false)
		})

		it("should throw error for invalid commands", () => {
			expect(() => {
				createSecureCommandWrapper("rm", ["-rf", "/"], {
					securityLevel: SecurityLevel.STRICT,
				})
			}).toThrow(CommandValidationError)
		})

		it("should filter environment variables", () => {
			const wrapper = createSecureCommandWrapper("node", ["index.js"], {
				env: {
					NODE_ENV: "production",
					MALICIOUS_VAR: "rm -rf /",
					PATH: "/usr/bin",
				},
				securityLevel: SecurityLevel.STRICT,
			})

			expect(wrapper.options.env.NODE_ENV).toBe("production")
			expect(wrapper.options.env.PATH).toBe("/usr/bin")
			expect(wrapper.options.env.MALICIOUS_VAR).toBeUndefined()
		})

		it("should validate working directory", () => {
			expect(() => {
				createSecureCommandWrapper("node", ["index.js"], {
					cwd: "../../../etc",
					securityLevel: SecurityLevel.STRICT,
				})
			}).toThrow(CommandValidationError)
		})
	})

	describe("getDefaultCommandConfig", () => {
		it("should return strict config for strict security level", () => {
			const config = getDefaultCommandConfig(SecurityLevel.STRICT)

			expect(config.securityLevel).toBe(SecurityLevel.STRICT)
			expect(config.allowedCommands).toContain("node")
			expect(config.allowAbsolutePaths).toBe(false)
			expect(config.maxCommandLength).toBe(500)
		})

		it("should return moderate config for moderate security level", () => {
			const config = getDefaultCommandConfig(SecurityLevel.MODERATE)

			expect(config.securityLevel).toBe(SecurityLevel.MODERATE)
			expect(config.allowedCommands).toContain("node")
			expect(config.allowedCommands).toContain("git")
			expect(config.allowAbsolutePaths).toBe(true)
			expect(config.maxCommandLength).toBe(1000)
		})

		it("should return permissive config for permissive security level", () => {
			const config = getDefaultCommandConfig(SecurityLevel.PERMISSIVE)

			expect(config.securityLevel).toBe(SecurityLevel.PERMISSIVE)
			expect(config.allowedCommands).toHaveLength(0) // Empty means all allowed
			expect(config.allowAbsolutePaths).toBe(true)
			expect(config.maxCommandLength).toBe(2000)
		})
	})

	describe("Security edge cases", () => {
		it("should handle empty commands", () => {
			const result = validateCommand("", [], undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
		})

		it("should handle null/undefined arguments", () => {
			const result = validateCommand("node", undefined as any, undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(true)
			expect(result.sanitizedArgs).toEqual([])
		})

		it("should sanitize command and arguments", () => {
			const result = validateCommand("  node  ", ["  index.js  "], undefined, SecurityLevel.MODERATE)

			expect(result.sanitizedCommand).toBe("node")
			expect(result.sanitizedArgs).toEqual(["index.js"])
		})

		it("should detect encoded injection attempts", () => {
			const result = validateCommand("node", ["index.js%3B%20rm%20-rf%20%2F"], undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
		})
	})
})
