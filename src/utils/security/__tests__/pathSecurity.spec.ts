/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Tests for path security and validation utilities.
 */

import {
	validatePath,
	validateWorkingDirectory,
	securePathResolve,
	createPathValidator,
	PathSecurityError,
	getDefaultPathConfig,
	type PathSecurityConfig,
} from "../pathSecurity"
import { SecurityLevel } from "../validationSchemas"

describe("Path Security", () => {
	describe("validatePath", () => {
		it("should validate safe relative paths", () => {
			const result = validatePath("src/index.js", undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(true)
			expect(result.normalizedPath).toBe("src/index.js")
			expect(result.metadata.isRelative).toBe(true)
			expect(result.metadata.extension).toBe(".js")
			expect(result.violations).toHaveLength(0)
		})

		it("should validate safe absolute paths in moderate mode", () => {
			const result = validatePath("/home/user/project/index.js", undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(true)
			expect(result.metadata.isAbsolute).toBe(true)
			expect(result.metadata.extension).toBe(".js")
		})

		it("should block absolute paths in strict mode", () => {
			const result = validatePath("/home/user/project/index.js", undefined, SecurityLevel.STRICT)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "absolute_path_blocked")).toBe(true)
		})

		it("should detect path traversal attacks", () => {
			const result = validatePath("../../../etc/passwd", undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.metadata.containsTraversal).toBe(true)
			expect(result.violations.some((v) => v.type === "path_traversal")).toBe(true)
		})

		it("should detect URL encoded path traversal", () => {
			const result = validatePath("..%2F..%2F..%2Fetc%2Fpasswd", undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.metadata.containsTraversal).toBe(true)
		})

		it("should validate against blocked paths", () => {
			const config: Partial<PathSecurityConfig> = {
				blockedPaths: ["/etc", "/usr/bin"],
			}
			const result = validatePath("/etc/passwd", config, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "path_blocked")).toBe(true)
		})

		it("should validate against allowed base paths", () => {
			const config: Partial<PathSecurityConfig> = {
				allowedBasePaths: ["/home/user"],
			}
			const result = validatePath("/tmp/malicious", config, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "path_not_allowed")).toBe(true)
		})

		it("should validate file extensions", () => {
			const config: Partial<PathSecurityConfig> = {
				allowedExtensions: [".js", ".ts"],
			}
			const result = validatePath("script.exe", config, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "extension_not_allowed")).toBe(true)
		})

		it("should block dangerous file extensions", () => {
			const config: Partial<PathSecurityConfig> = {
				blockedExtensions: [".exe", ".bat"],
			}
			const result = validatePath("malware.exe", config, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "extension_blocked")).toBe(true)
		})

		it("should validate path length limits", () => {
			const longPath = "a".repeat(5000)
			const result = validatePath(longPath, undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "path_too_long")).toBe(true)
		})

		it("should detect dangerous characters", () => {
			const result = validatePath("file\x00name.txt", undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "dangerous_pattern")).toBe(true)
		})

		it("should detect Windows reserved names", () => {
			const result = validatePath("CON.txt", undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "dangerous_pattern")).toBe(true)
		})

		it("should normalize paths correctly", () => {
			const result = validatePath("./src/../src/index.js", undefined, SecurityLevel.MODERATE)

			expect(result.normalizedPath).toBe("src/index.js")
		})
	})

	describe("validateWorkingDirectory", () => {
		it("should validate safe working directories", () => {
			const result = validateWorkingDirectory("/home/user/project", ["/home/user"], SecurityLevel.MODERATE)

			expect(result.isValid).toBe(true)
			expect(result.violations).toHaveLength(0)
		})

		it("should reject paths with file extensions", () => {
			const result = validateWorkingDirectory("/home/user/script.js", [], SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "directory_has_extension")).toBe(true)
		})

		it("should validate against allowed directories", () => {
			const result = validateWorkingDirectory("/tmp/malicious", ["/home/user"], SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "path_not_allowed")).toBe(true)
		})
	})

	describe("securePathResolve", () => {
		it("should resolve safe paths", () => {
			const resolved = securePathResolve("/home/user", "project/index.js", SecurityLevel.MODERATE)

			expect(resolved).toContain("project/index.js")
		})

		it("should prevent path escape attacks", () => {
			expect(() => {
				securePathResolve("/home/user", "../../../etc/passwd", SecurityLevel.MODERATE)
			}).toThrow(PathSecurityError)
		})

		it("should validate base path", () => {
			expect(() => {
				securePathResolve("../../../etc", "passwd", SecurityLevel.MODERATE)
			}).toThrow(PathSecurityError)
		})

		it("should validate relative path", () => {
			expect(() => {
				securePathResolve("/home/user", "malware.exe", SecurityLevel.STRICT)
			}).toThrow(PathSecurityError)
		})
	})

	describe("createPathValidator", () => {
		it("should create validator with custom config", () => {
			const config: Partial<PathSecurityConfig> = {
				allowedExtensions: [".js", ".ts"],
				maxPathLength: 100,
			}
			const validator = createPathValidator(config, SecurityLevel.MODERATE)

			const result = validator("script.py")
			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "extension_not_allowed")).toBe(true)
		})

		it("should use security level defaults", () => {
			const validator = createPathValidator(undefined, SecurityLevel.STRICT)

			const result = validator("/absolute/path")
			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "absolute_path_blocked")).toBe(true)
		})
	})

	describe("getDefaultPathConfig", () => {
		it("should return strict config for strict security level", () => {
			const config = getDefaultPathConfig(SecurityLevel.STRICT)

			expect(config.securityLevel).toBe(SecurityLevel.STRICT)
			expect(config.allowAbsolutePaths).toBe(false)
			expect(config.allowSymlinks).toBe(false)
			expect(config.maxPathLength).toBe(260)
			expect(config.blockedExtensions).toContain(".exe")
		})

		it("should return moderate config for moderate security level", () => {
			const config = getDefaultPathConfig(SecurityLevel.MODERATE)

			expect(config.securityLevel).toBe(SecurityLevel.MODERATE)
			expect(config.allowAbsolutePaths).toBe(true)
			expect(config.allowSymlinks).toBe(false)
			expect(config.maxPathLength).toBe(1024)
		})

		it("should return permissive config for permissive security level", () => {
			const config = getDefaultPathConfig(SecurityLevel.PERMISSIVE)

			expect(config.securityLevel).toBe(SecurityLevel.PERMISSIVE)
			expect(config.allowAbsolutePaths).toBe(true)
			expect(config.allowSymlinks).toBe(true)
			expect(config.maxPathLength).toBe(4096)
			expect(config.blockedPaths).toHaveLength(0)
		})
	})

	describe("Security edge cases", () => {
		it("should handle empty paths", () => {
			const result = validatePath("", undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "invalid_input")).toBe(true)
		})

		it("should handle null/undefined paths", () => {
			const result = validatePath(null as any, undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
			expect(result.violations.some((v) => v.type === "invalid_input")).toBe(true)
		})

		it("should handle paths with only whitespace", () => {
			const result = validatePath("   ", undefined, SecurityLevel.MODERATE)

			expect(result.isValid).toBe(false)
		})

		it("should calculate path depth correctly", () => {
			const result = validatePath("a/b/c/d/e.txt", undefined, SecurityLevel.MODERATE)

			expect(result.metadata.depth).toBe(5)
		})

		it("should handle Windows-style paths", () => {
			const result = validatePath("C:\\Users\\test\\file.txt", undefined, SecurityLevel.MODERATE)

			expect(result.metadata.isAbsolute).toBe(true)
			expect(result.normalizedPath).toContain("file.txt")
		})

		it("should handle mixed path separators", () => {
			const result = validatePath("path\\to/mixed\\separators", undefined, SecurityLevel.MODERATE)

			expect(result.normalizedPath).not.toContain("\\")
		})
	})

	describe("PathSecurityError", () => {
		it("should create error with violations", () => {
			const violations = [{ type: "test", message: "test violation", severity: "high" as const }]
			const error = new PathSecurityError("Test error", violations, "/test/path")

			expect(error.message).toBe("Test error")
			expect(error.violations).toEqual(violations)
			expect(error.path).toBe("/test/path")
			expect(error.name).toBe("PathSecurityError")
		})
	})
})
