/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 */
import {
	sanitizeString,
	sanitizeObject,
	sanitizeArray,
	sanitizeValue,
	validateSanitizedValue,
	createSanitizationConfig,
	SecurityValidationError,
	DEFAULT_SANITIZATION_CONFIG,
} from "../inputSanitizer"

describe("inputSanitizer", () => {
	describe("sanitizeString", () => {
		it("should sanitize normal strings without modification", () => {
			const input = "Hello world"
			const result = sanitizeString(input, "test")
			expect(result).toBe("Hello world")
		})

		it("should throw error for strings exceeding length limit", () => {
			const longString = "a".repeat(10001)
			expect(() => sanitizeString(longString, "test")).toThrow(SecurityValidationError)
			expect(() => sanitizeString(longString, "test")).toThrow("String exceeds maximum length")
		})

		it("should detect and block command injection patterns", () => {
			const maliciousInputs = [
				"rm -rf /",
				"cat /etc/passwd",
				"$(whoami)",
				"`ls -la`",
				"test; rm file",
				"test | grep secret",
				"test && malicious",
			]

			maliciousInputs.forEach((input) => {
				expect(() => sanitizeString(input, "test")).toThrow(SecurityValidationError)
			})
		})

		it("should detect and block SQL injection patterns", () => {
			const sqlInjections = [
				"'; DROP TABLE users; --",
				"UNION SELECT * FROM passwords",
				"INSERT INTO admin VALUES",
				"UPDATE users SET password",
				"DELETE FROM sensitive_data",
			]

			sqlInjections.forEach((input) => {
				expect(() => sanitizeString(input, "test")).toThrow(SecurityValidationError)
			})
		})

		it("should detect and block XSS patterns", () => {
			const xssInputs = ["<script>alert('xss')</script>", "javascript:alert(1)", "vbscript:msgbox(1)"]

			xssInputs.forEach((input) => {
				expect(() => sanitizeString(input, "test")).toThrow(SecurityValidationError)
			})
		})

		it("should detect and block path traversal patterns", () => {
			const pathTraversals = ["../../../etc/passwd", "..\\..\\windows\\system32", "./../../secret.txt"]

			pathTraversals.forEach((input) => {
				expect(() => sanitizeString(input, "test")).toThrow(SecurityValidationError)
			})
		})

		it("should block file paths when not allowed", () => {
			const filePaths = [
				"/etc/passwd",
				"C:\\Windows\\System32",
				"./config.json",
				"../data/secret.txt",
				"path/to/file.txt",
			]

			const config = createSanitizationConfig({ allowFilePaths: false })
			filePaths.forEach((input) => {
				expect(() => sanitizeString(input, "test", config)).toThrow(SecurityValidationError)
			})
		})

		it("should allow file paths when configured", () => {
			const filePaths = ["/etc/passwd", "./config.json", "path/to/file.txt"]

			const config = createSanitizationConfig({ allowFilePaths: true })
			filePaths.forEach((input) => {
				expect(() => sanitizeString(input, "test", config)).not.toThrow()
			})
		})

		it("should block URLs when not allowed", () => {
			const urls = [
				"http://example.com",
				"https://malicious.site",
				"ftp://files.example.com",
				"//example.com/path",
			]

			const config = createSanitizationConfig({ allowUrls: false })
			urls.forEach((input) => {
				expect(() => sanitizeString(input, "test", config)).toThrow(SecurityValidationError)
			})
		})

		it("should allow URLs when configured", () => {
			const urls = ["http://example.com", "https://safe.site"]

			const config = createSanitizationConfig({ allowUrls: true, allowFilePaths: true })
			urls.forEach((input) => {
				expect(() => sanitizeString(input, "test", config)).not.toThrow()
			})
		})

		it("should block shell commands when not allowed", () => {
			const shellCommands = ["sudo rm -rf /", "chmod 777 file", "eval malicious_code", "source ~/.bashrc"]

			const config = createSanitizationConfig({ allowShellCommands: false })
			shellCommands.forEach((input) => {
				expect(() => sanitizeString(input, "test", config)).toThrow(SecurityValidationError)
			})
		})

		it("should remove null bytes and normalize whitespace", () => {
			const input = "  test\0string  \n"
			const result = sanitizeString(input, "test")
			expect(result).toBe("teststring")
		})

		it("should use custom blocked patterns", () => {
			const config = createSanitizationConfig({
				blockedPatterns: ["forbidden", "blocked"],
			})

			expect(() => sanitizeString("this is forbidden", "test", config)).toThrow(SecurityValidationError)
			expect(() => sanitizeString("blocked content", "test", config)).toThrow(SecurityValidationError)
			expect(() => sanitizeString("allowed content", "test", config)).not.toThrow()
		})
	})

	describe("sanitizeObject", () => {
		it("should sanitize simple objects", () => {
			const input = { key: "value", number: 42 }
			const result = sanitizeObject(input, "test")
			expect(result).toEqual({ key: "value", number: 42 })
		})

		it("should throw error for objects exceeding depth limit", () => {
			const deepObject = {
				a: { b: { c: { d: { e: { f: { g: { h: { i: { j: { k: { l: "deep" } } } } } } } } } } },
			}
			expect(() => sanitizeObject(deepObject, "test")).toThrow(SecurityValidationError)
			expect(() => sanitizeObject(deepObject, "test")).toThrow("exceeds maximum depth")
		})

		it("should throw error for objects with too many properties", () => {
			const largeObject: Record<string, string> = {}
			for (let i = 0; i < 101; i++) {
				largeObject[`key${i}`] = `value${i}`
			}
			expect(() => sanitizeObject(largeObject, "test")).toThrow(SecurityValidationError)
			expect(() => sanitizeObject(largeObject, "test")).toThrow("exceeds maximum properties")
		})

		it("should recursively sanitize nested objects", () => {
			const input = {
				safe: "value",
				nested: {
					key: "  trimmed  ",
				},
			}
			const result = sanitizeObject(input, "test")
			expect(result).toEqual({
				safe: "value",
				nested: {
					key: "trimmed",
				},
			})
		})

		it("should sanitize object keys", () => {
			const input = { "  key  ": "value" }
			const result = sanitizeObject(input, "test")
			expect(result).toEqual({ key: "value" })
		})
	})

	describe("sanitizeArray", () => {
		it("should sanitize simple arrays", () => {
			const input = ["value1", "value2", 42]
			const result = sanitizeArray(input, "test")
			expect(result).toEqual(["value1", "value2", 42])
		})

		it("should throw error for arrays exceeding length limit", () => {
			const largeArray = new Array(1001).fill("item")
			expect(() => sanitizeArray(largeArray, "test")).toThrow(SecurityValidationError)
			expect(() => sanitizeArray(largeArray, "test")).toThrow("exceeds maximum length")
		})

		it("should recursively sanitize array elements", () => {
			const input = ["  trimmed  ", { key: "  value  " }]
			const result = sanitizeArray(input, "test")
			expect(result).toEqual(["trimmed", { key: "value" }])
		})
	})

	describe("sanitizeValue", () => {
		it("should handle null and undefined", () => {
			expect(sanitizeValue(null, "test")).toBe(null)
			expect(sanitizeValue(undefined, "test")).toBe(undefined)
		})

		it("should handle primitive types", () => {
			expect(sanitizeValue("string", "test")).toBe("string")
			expect(sanitizeValue(42, "test")).toBe(42)
			expect(sanitizeValue(true, "test")).toBe(true)
		})

		it("should handle arrays", () => {
			const input = ["item1", "item2"]
			const result = sanitizeValue(input, "test")
			expect(result).toEqual(["item1", "item2"])
		})

		it("should handle objects", () => {
			const input = { key: "value" }
			const result = sanitizeValue(input, "test")
			expect(result).toEqual({ key: "value" })
		})

		it("should convert unknown types to strings", () => {
			const symbol = Symbol("test")
			// Use a config that allows the symbol string representation
			const config = createSanitizationConfig({
				blockedPatterns: [], // Remove all blocked patterns for this test
				allowShellCommands: true, // Allow shell commands since Symbol() contains parentheses
			})
			const result = sanitizeValue(symbol, "test", config)
			expect(typeof result).toBe("string")
		})
	})

	describe("validateSanitizedValue", () => {
		it("should pass validation for safe values", () => {
			expect(() => validateSanitizedValue("safe string", "test")).not.toThrow()
			expect(() => validateSanitizedValue({ key: "value" }, "test")).not.toThrow()
			expect(() => validateSanitizedValue(42, "test")).not.toThrow()
		})

		it("should detect encoded injection attempts", () => {
			const encodedInputs = [
				"test%3Cscript%3E", // URL encoded <script>
				"test&#60;script&#62;", // HTML entity encoded <script>
				"test\\x3cscript\\x3e", // Hex encoded <script>
				"test\\u003cscript\\u003e", // Unicode encoded <script>
			]

			encodedInputs.forEach((input) => {
				expect(() => validateSanitizedValue(input, "test")).toThrow(SecurityValidationError)
			})
		})
	})

	describe("createSanitizationConfig", () => {
		it("should create config with default values", () => {
			const config = createSanitizationConfig({})
			expect(config.maxStringLength).toBe(DEFAULT_SANITIZATION_CONFIG.maxStringLength)
			expect(config.allowFilePaths).toBe(DEFAULT_SANITIZATION_CONFIG.allowFilePaths)
		})

		it("should override specific values", () => {
			const config = createSanitizationConfig({
				maxStringLength: 500,
				allowFilePaths: true,
			})
			expect(config.maxStringLength).toBe(500)
			expect(config.allowFilePaths).toBe(true)
			expect(config.maxObjectDepth).toBe(DEFAULT_SANITIZATION_CONFIG.maxObjectDepth)
		})
	})

	describe("SecurityValidationError", () => {
		it("should create error with proper properties", () => {
			const error = new SecurityValidationError("Test error", "testField", "testValue", "test_violation")

			expect(error.message).toBe("Test error")
			expect(error.field).toBe("testField")
			expect(error.value).toBe("testValue")
			expect(error.violationType).toBe("test_violation")
			expect(error.name).toBe("SecurityValidationError")
		})
	})
})
