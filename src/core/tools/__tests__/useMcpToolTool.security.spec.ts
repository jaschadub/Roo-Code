/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 */
// Integration tests for useMcpToolTool with security validation framework

import { useMcpToolTool } from "../useMcpToolTool"
import { Task } from "../../task/Task"
import { ToolUse } from "../../../shared/tools"
import { getSecurityManager, SecurityLevel } from "../../../utils/security"

// Mock dependencies
vi.mock("../../prompts/responses", () => ({
	formatResponse: {
		toolResult: vi.fn((result: string) => `Tool result: ${result}`),
		toolError: vi.fn((error: string) => `Tool error: ${error}`),
		invalidMcpToolArgumentError: vi.fn((server: string, tool: string) => `Invalid args for ${server}:${tool}`),
	},
}))

vi.mock("../../../i18n", () => ({
	t: vi.fn((key: string, params?: any) => {
		if (key === "mcp:errors.invalidJsonArgument" && params?.toolName) {
			return `Roo tried to use ${params.toolName} with an invalid JSON argument. Retrying...`
		}
		return key
	}),
}))

// Mock SchemaPin service
vi.mock("../../../services/schemapin", () => ({
	SchemaPinService: vi.fn().mockImplementation(() => ({
		initialize: vi.fn().mockResolvedValue(undefined),
		isEnabled: vi.fn().mockReturnValue(true),
		verifyMcpTool: vi.fn().mockResolvedValue({
			valid: true,
			pinned: false,
			firstUse: false,
		}),
		dispose: vi.fn().mockResolvedValue(undefined),
	})),
}))

describe("useMcpToolTool - Security Integration", () => {
	let mockTask: Partial<Task>
	let mockAskApproval: ReturnType<typeof vi.fn>
	let mockHandleError: ReturnType<typeof vi.fn>
	let mockPushToolResult: ReturnType<typeof vi.fn>
	let mockRemoveClosingTag: ReturnType<typeof vi.fn>
	let mockProviderRef: any

	beforeEach(() => {
		// Reset security manager before each test
		getSecurityManager().reset()

		mockAskApproval = vi.fn()
		mockHandleError = vi.fn()
		mockPushToolResult = vi.fn()
		mockRemoveClosingTag = vi.fn((tag: string, value?: string) => value || "")

		mockProviderRef = {
			deref: vi.fn().mockReturnValue({
				getMcpHub: vi.fn().mockReturnValue({
					callTool: vi.fn().mockResolvedValue({
						content: [{ type: "text", text: "Tool executed successfully" }],
						isError: false,
					}),
					getAllServers: vi.fn().mockReturnValue([
						{
							name: "test_server",
							tools: [
								{
									name: "test_tool",
									inputSchema: { type: "object", properties: { param: { type: "string" } } },
								},
							],
						},
					]),
				}),
				postMessageToWebview: vi.fn(),
				context: {
					globalState: {
						get: vi.fn(),
						update: vi.fn(),
					},
					globalStorageUri: {
						fsPath: "/mock/path",
					},
				},
			}),
		}

		mockTask = {
			consecutiveMistakeCount: 0,
			recordToolError: vi.fn(),
			sayAndCreateMissingParamError: vi.fn(),
			say: vi.fn(),
			ask: vi.fn(),
			lastMessageTs: 123456789,
			providerRef: mockProviderRef,
		}
	})

	describe("security validation", () => {
		it("should block malicious server names", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "malicious; rm -rf /",
					tool_name: "test_tool",
					arguments: "{}",
				},
				partial: false,
			}

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.recordToolError).toHaveBeenCalledWith("use_mcp_tool")
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("Security violation"))
			expect(mockPushToolResult).toHaveBeenCalledWith(expect.stringContaining("Tool error:"))
		})

		it("should block malicious tool names", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "malicious`command`",
					arguments: "{}",
				},
				partial: false,
			}

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("Security violation"))
		})

		it("should block command injection in arguments", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: '{"command": "rm -rf /"}',
				},
				partial: false,
			}

			// Configure strict security for this test
			getSecurityManager().updatePolicy({
				defaultSecurityLevel: SecurityLevel.STRICT,
			})

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("Security violation"))
		})

		it("should block SQL injection attempts", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: '{"query": "SELECT * FROM users; DROP TABLE passwords;"}',
				},
				partial: false,
			}

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("Security violation"))
		})

		it("should block XSS attempts", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: '{"content": "<script>alert(\\"xss\\")</script>"}',
				},
				partial: false,
			}

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("Security violation"))
		})

		it("should sanitize and allow safe parameters", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "  test_server  ",
					tool_name: "  test_tool  ",
					arguments: '{"message": "  Hello World  ", "count": 42}',
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(0)
			expect(mockAskApproval).toHaveBeenCalled()
			expect(mockTask.say).toHaveBeenCalledWith("mcp_server_request_started")
		})

		it("should handle deeply nested objects within limits", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: JSON.stringify({
						level1: {
							level2: {
								level3: {
									data: "safe content",
								},
							},
						},
					}),
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(0)
			expect(mockAskApproval).toHaveBeenCalled()
		})

		it("should block excessively deep objects", async () => {
			// Create a deeply nested object that exceeds limits
			let deepObject: any = { data: "value" }
			for (let i = 0; i < 15; i++) {
				deepObject = { nested: deepObject }
			}

			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: JSON.stringify(deepObject),
				},
				partial: false,
			}

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("Security violation"))
		})

		it("should track security violations per server", async () => {
			const securityManager = getSecurityManager()

			// First violation
			const block1: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "malicious_server",
					tool_name: "bad; command",
					arguments: "{}",
				},
				partial: false,
			}

			await useMcpToolTool(
				mockTask as Task,
				block1,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			// Second violation
			const block2: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "malicious_server",
					tool_name: "another`bad`tool",
					arguments: "{}",
				},
				partial: false,
			}

			await useMcpToolTool(
				mockTask as Task,
				block2,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			const metrics = securityManager.getMetrics()
			expect(metrics.violationsByServer["malicious_server"]).toBe(2)
			expect(metrics.totalViolations).toBe(2)
		})

		it("should apply server-specific security levels", async () => {
			// Configure different security levels for different servers
			getSecurityManager().updatePolicy({
				defaultSecurityLevel: SecurityLevel.MODERATE,
				serverSpecificRules: {
					trusted_server: { defaultSecurityLevel: SecurityLevel.PERMISSIVE },
					untrusted_server: { defaultSecurityLevel: SecurityLevel.STRICT },
				},
			})

			// Test with trusted server (should be more permissive)
			const trustedBlock: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "trusted_server",
					tool_name: "test_tool",
					arguments: '{"path": "/home/user/file.txt"}',
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await useMcpToolTool(
				mockTask as Task,
				trustedBlock,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(0)

			// Reset for next test
			mockTask.consecutiveMistakeCount = 0
			mockAskApproval.mockClear()
			mockPushToolResult.mockClear()

			// Test with untrusted server (should be more strict)
			const untrustedBlock: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "untrusted_server",
					tool_name: "test_tool",
					arguments: '{"path": "/home/user/file.txt"}',
				},
				partial: false,
			}

			await useMcpToolTool(
				mockTask as Task,
				untrustedBlock,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("Security violation"))
		})
	})

	describe("backward compatibility", () => {
		it("should maintain compatibility with existing valid calls", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: '{"param": "value"}',
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(0)
			expect(mockAskApproval).toHaveBeenCalled()
			expect(mockTask.say).toHaveBeenCalledWith("mcp_server_request_started")
			expect(mockTask.say).toHaveBeenCalledWith("mcp_server_response", "Tool executed successfully")
		})

		it("should handle missing parameters with original error messages", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					tool_name: "test_tool",
					arguments: "{}",
				},
				partial: false,
			}

			mockTask.sayAndCreateMissingParamError = vi.fn().mockResolvedValue("Missing server_name error")

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.recordToolError).toHaveBeenCalledWith("use_mcp_tool")
		})
	})
})
