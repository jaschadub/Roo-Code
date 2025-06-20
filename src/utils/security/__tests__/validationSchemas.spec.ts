/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 */
import {
	SecurityLevel,
	serverNameSchema,
	toolNameSchema,
	uriSchema,
	createToolArgumentsSchema,
	createMcpToolParamsSchema,
	createMcpResourceParamsSchema,
	validateMcpToolParams,
	validateMcpResourceParams,
} from "../validationSchemas"

describe("validationSchemas", () => {
	describe("serverNameSchema", () => {
		it("should validate valid server names", () => {
			const validNames = ["test_server", "server_name", "server123", "my_test_server_v1"]

			validNames.forEach((name) => {
				expect(() => serverNameSchema.parse(name)).not.toThrow()
			})
		})

		it("should reject invalid server names", () => {
			const invalidNames = [
				"", // empty
				"a".repeat(101), // too long
				"server with spaces",
				"server@domain",
				"server#hash",
				"server/path",
				"server\\path",
				"server;command",
				"server|pipe",
			]

			invalidNames.forEach((name) => {
				expect(() => serverNameSchema.parse(name)).toThrow()
			})
		})

		it("should sanitize server names", () => {
			const input = "  test_server  "
			const result = serverNameSchema.parse(input)
			expect(result).toBe("test_server")
		})
	})

	describe("toolNameSchema", () => {
		it("should validate valid tool names", () => {
			const validNames = ["test_tool", "tool_name", "tool123", "my_test_tool_v1"]

			validNames.forEach((name) => {
				expect(() => toolNameSchema.parse(name)).not.toThrow()
			})
		})

		it("should reject invalid tool names", () => {
			const invalidNames = [
				"", // empty
				"a".repeat(101), // too long
				"tool with spaces",
				"tool@action",
				"tool#hash",
				"tool/action",
				"tool\\action",
				"tool;command",
				"tool|pipe",
			]

			invalidNames.forEach((name) => {
				expect(() => toolNameSchema.parse(name)).toThrow()
			})
		})
	})

	describe("uriSchema", () => {
		it("should validate valid URIs", () => {
			const validUris = [
				"http://example.com",
				"https://api.example.com/resource",
				"file:///path/to/file",
				"custom://protocol/resource",
				"resource-name",
				"path/to/resource",
			]

			validUris.forEach((uri) => {
				expect(() => uriSchema.parse(uri)).not.toThrow()
			})
		})

		it("should reject invalid URIs", () => {
			const invalidUris = [
				"", // empty
				"a".repeat(2001), // too long
				"javascript:alert(1)", // blocked protocol
				"vbscript:msgbox(1)", // blocked protocol
			]

			invalidUris.forEach((uri) => {
				expect(() => uriSchema.parse(uri)).toThrow()
			})
		})

		it("should sanitize URIs", () => {
			const input = "  http://example.com/path  "
			const result = uriSchema.parse(input)
			expect(result).toBe("http://example.com/path")
		})
	})

	describe("createToolArgumentsSchema", () => {
		it("should validate null and undefined arguments", () => {
			const schema = createToolArgumentsSchema(SecurityLevel.MODERATE)

			expect(() => schema.parse(null)).not.toThrow()
			expect(() => schema.parse(undefined)).not.toThrow()
		})

		it("should validate string arguments", () => {
			const schema = createToolArgumentsSchema(SecurityLevel.MODERATE)

			expect(() => schema.parse("simple string")).not.toThrow()
			expect(() => schema.parse('{"key": "value"}')).not.toThrow()
		})

		it("should validate object arguments", () => {
			const schema = createToolArgumentsSchema(SecurityLevel.MODERATE)
			const validArgs = { key: "value", number: 42, nested: { prop: "val" } }

			expect(() => schema.parse(validArgs)).not.toThrow()
		})

		it("should validate array arguments", () => {
			const schema = createToolArgumentsSchema(SecurityLevel.MODERATE)
			const validArgs = ["item1", "item2", { key: "value" }]

			expect(() => schema.parse(validArgs)).not.toThrow()
		})

		it("should reject arguments that are too large", () => {
			const schema = createToolArgumentsSchema(SecurityLevel.STRICT)
			const largeObject: Record<string, string> = {}

			// Create an object that will exceed size limits when serialized
			for (let i = 0; i < 1000; i++) {
				largeObject[`key${i}`] = "a".repeat(100)
			}

			expect(() => schema.parse(largeObject)).toThrow()
		})

		it("should parse JSON strings", () => {
			const schema = createToolArgumentsSchema(SecurityLevel.MODERATE)
			const jsonString = '{"key": "value", "number": 42}'
			const result = schema.parse(jsonString)

			expect(result).toEqual({ key: "value", number: 42 })
		})

		it("should handle invalid JSON strings", () => {
			const schema = createToolArgumentsSchema(SecurityLevel.MODERATE)
			const invalidJson = "invalid json string"
			const result = schema.parse(invalidJson)

			expect(result).toBe("invalid json string")
		})

		it("should apply different security levels", () => {
			const strictSchema = createToolArgumentsSchema(SecurityLevel.STRICT)
			const moderateSchema = createToolArgumentsSchema(SecurityLevel.MODERATE)
			const permissiveSchema = createToolArgumentsSchema(SecurityLevel.PERMISSIVE)

			// Test with a moderately complex object
			const testArgs = {
				command: "ls -la",
				path: "/home/user",
				options: { recursive: true },
			}

			// Strict should be more restrictive
			expect(() => strictSchema.parse(testArgs)).toThrow()

			// Moderate and permissive should allow it
			expect(() => moderateSchema.parse(testArgs)).not.toThrow()
			expect(() => permissiveSchema.parse(testArgs)).not.toThrow()
		})
	})

	describe("createMcpToolParamsSchema", () => {
		it("should validate complete valid parameters", () => {
			const schema = createMcpToolParamsSchema(SecurityLevel.MODERATE)
			const validParams = {
				server_name: "test-server",
				tool_name: "test-tool",
				arguments: { key: "value" },
			}

			expect(() => schema.parse(validParams)).not.toThrow()
		})

		it("should validate parameters without arguments", () => {
			const schema = createMcpToolParamsSchema(SecurityLevel.MODERATE)
			const validParams = {
				server_name: "test-server",
				tool_name: "test-tool",
			}

			expect(() => schema.parse(validParams)).not.toThrow()
		})

		it("should reject parameters with missing required fields", () => {
			const schema = createMcpToolParamsSchema(SecurityLevel.MODERATE)

			expect(() => schema.parse({ tool_name: "test-tool" })).toThrow()
			expect(() => schema.parse({ server_name: "test-server" })).toThrow()
			expect(() => schema.parse({})).toThrow()
		})

		it("should sanitize all parameters", () => {
			const schema = createMcpToolParamsSchema(SecurityLevel.MODERATE)
			const params = {
				server_name: "  test_server  ",
				tool_name: "  test_tool  ",
				arguments: "  simple string  ",
			}

			const result = schema.parse(params)
			expect(result.server_name).toBe("test_server")
			expect(result.tool_name).toBe("test_tool")
			expect(result.arguments).toBe("simple string")
		})
	})

	describe("createMcpResourceParamsSchema", () => {
		it("should validate complete valid parameters", () => {
			const schema = createMcpResourceParamsSchema(SecurityLevel.MODERATE)
			const validParams = {
				server_name: "test-server",
				uri: "http://example.com/resource",
			}

			expect(() => schema.parse(validParams)).not.toThrow()
		})

		it("should reject parameters with missing required fields", () => {
			const schema = createMcpResourceParamsSchema(SecurityLevel.MODERATE)

			expect(() => schema.parse({ uri: "http://example.com" })).toThrow()
			expect(() => schema.parse({ server_name: "test-server" })).toThrow()
			expect(() => schema.parse({})).toThrow()
		})

		it("should sanitize all parameters", () => {
			const schema = createMcpResourceParamsSchema(SecurityLevel.MODERATE)
			const params = {
				server_name: "  test_server  ",
				uri: "  http://example.com/resource  ",
			}

			const result = schema.parse(params)
			expect(result.server_name).toBe("test_server")
			expect(result.uri).toBe("http://example.com/resource")
		})
	})

	describe("validateMcpToolParams", () => {
		it("should return success for valid parameters", () => {
			const params = {
				server_name: "test-server",
				tool_name: "test-tool",
				arguments: { key: "value" },
			}

			const result = validateMcpToolParams(params, SecurityLevel.MODERATE)

			expect(result.success).toBe(true)
			expect(result.data).toBeDefined()
			expect(result.data?.server_name).toBe("test-server")
			expect(result.data?.tool_name).toBe("test-tool")
			expect(result.context.securityLevel).toBe(SecurityLevel.MODERATE)
		})

		it("should return failure for invalid parameters", () => {
			const params = {
				server_name: "invalid server name with spaces",
				tool_name: "test-tool",
			}

			const result = validateMcpToolParams(params, SecurityLevel.STRICT)

			expect(result.success).toBe(false)
			expect(result.securityViolations || result.errors).toBeDefined()
			expect(result.data).toBeUndefined()
		})

		it("should detect security violations", () => {
			const params = {
				server_name: "test-server",
				tool_name: "test-tool",
				arguments: "rm -rf /",
			}

			const result = validateMcpToolParams(params, SecurityLevel.STRICT)

			expect(result.success).toBe(false)
			expect(result.securityViolations).toBeDefined()
			expect(result.securityViolations!.length).toBeGreaterThan(0)
		})

		it("should include validation context", () => {
			const params = {
				server_name: "test-server",
				tool_name: "test-tool",
			}

			const context = {
				toolName: "custom-tool",
				userAgent: "test-agent",
			}

			const result = validateMcpToolParams(params, SecurityLevel.MODERATE, context)

			expect(result.context.toolName).toBe("custom-tool")
			expect(result.context.userAgent).toBe("test-agent")
			expect(result.context.securityLevel).toBe(SecurityLevel.MODERATE)
			expect(result.context.timestamp).toBeDefined()
		})
	})

	describe("validateMcpResourceParams", () => {
		it("should return success for valid parameters", () => {
			const params = {
				server_name: "test-server",
				uri: "http://example.com/resource",
			}

			const result = validateMcpResourceParams(params, SecurityLevel.MODERATE)

			expect(result.success).toBe(true)
			expect(result.data).toBeDefined()
			expect(result.data?.server_name).toBe("test-server")
			expect(result.data?.uri).toBe("http://example.com/resource")
		})

		it("should return failure for invalid parameters", () => {
			const params = {
				server_name: "invalid server name",
				uri: "javascript:alert(1)",
			}

			const result = validateMcpResourceParams(params, SecurityLevel.STRICT)

			expect(result.success).toBe(false)
			expect(result.securityViolations || result.errors).toBeDefined()
		})

		it("should detect security violations in URIs", () => {
			const params = {
				server_name: "test-server",
				uri: "javascript:alert('xss')",
			}

			const result = validateMcpResourceParams(params, SecurityLevel.MODERATE)

			expect(result.success).toBe(false)
			expect(result.securityViolations).toBeDefined()
		})
	})

	describe("SecurityLevel enum", () => {
		it("should have expected values", () => {
			expect(SecurityLevel.STRICT).toBe("strict")
			expect(SecurityLevel.MODERATE).toBe("moderate")
			expect(SecurityLevel.PERMISSIVE).toBe("permissive")
		})
	})
})
