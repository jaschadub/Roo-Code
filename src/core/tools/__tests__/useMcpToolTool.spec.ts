// npx vitest core/tools/__tests__/useMcpToolTool.spec.ts

import { useMcpToolTool } from "../useMcpToolTool"
import { Task } from "../../task/Task"
import { ToolUse } from "../../../shared/tools"

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

describe("useMcpToolTool", () => {
	let mockTask: Partial<Task>
	let mockAskApproval: ReturnType<typeof vi.fn>
	let mockHandleError: ReturnType<typeof vi.fn>
	let mockPushToolResult: ReturnType<typeof vi.fn>
	let mockRemoveClosingTag: ReturnType<typeof vi.fn>
	let mockProviderRef: any

	beforeEach(() => {
		mockAskApproval = vi.fn()
		mockHandleError = vi.fn()
		mockPushToolResult = vi.fn()
		mockRemoveClosingTag = vi.fn((tag: string, value?: string) => value || "")

		mockProviderRef = {
			deref: vi.fn().mockReturnValue({
				getMcpHub: vi.fn().mockReturnValue({
					callTool: vi.fn(),
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

	describe("parameter validation", () => {
		it("should handle missing server_name", async () => {
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
			expect(mockTask.sayAndCreateMissingParamError).toHaveBeenCalledWith("use_mcp_tool", "server_name")
			expect(mockPushToolResult).toHaveBeenCalledWith("Missing server_name error")
		})

		it("should handle missing tool_name", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					arguments: "{}",
				},
				partial: false,
			}

			mockTask.sayAndCreateMissingParamError = vi.fn().mockResolvedValue("Missing tool_name error")

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
			expect(mockTask.sayAndCreateMissingParamError).toHaveBeenCalledWith("use_mcp_tool", "tool_name")
			expect(mockPushToolResult).toHaveBeenCalledWith("Missing tool_name error")
		})

		it("should handle invalid JSON arguments", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: "invalid json",
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
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("invalid JSON argument"))
			expect(mockPushToolResult).toHaveBeenCalledWith("Tool error: Invalid args for test_server:test_tool")
		})
	})

	describe("partial requests", () => {
		it("should handle partial requests", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: "{}",
				},
				partial: true,
			}

			mockTask.ask = vi.fn().mockResolvedValue(true)

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.ask).toHaveBeenCalledWith("use_mcp_server", expect.stringContaining("use_mcp_tool"), true)
		})
	})

	describe("successful execution", () => {
		it("should execute tool successfully with valid parameters", async () => {
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

			const mockToolResult = {
				content: [{ type: "text", text: "Tool executed successfully" }],
				isError: false,
			}

			mockProviderRef.deref.mockReturnValue({
				getMcpHub: () => ({
					callTool: vi.fn().mockResolvedValue(mockToolResult),
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
			})

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
			expect(mockPushToolResult).toHaveBeenCalledWith("Tool result: Tool executed successfully")
		})

		it("should handle user rejection", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
					arguments: "{}",
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(false)

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.say).not.toHaveBeenCalledWith("mcp_server_request_started")
			expect(mockPushToolResult).not.toHaveBeenCalled()
		})
	})

	describe("error handling", () => {
		it("should handle unexpected errors", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "use_mcp_tool",
				params: {
					server_name: "test_server",
					tool_name: "test_tool",
				},
				partial: false,
			}

			const error = new Error("Unexpected error")
			mockAskApproval.mockRejectedValue(error)

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockHandleError).toHaveBeenCalledWith("executing MCP tool", error)
		})
	})

	describe("SchemaPin integration", () => {
		it("should perform schema verification when SchemaPin is enabled", async () => {
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

			const mockToolResult = {
				content: [{ type: "text", text: "Tool executed successfully" }],
				isError: false,
			}

			const mockSchemaPinService = {
				initialize: vi.fn().mockResolvedValue(undefined),
				isEnabled: vi.fn().mockReturnValue(true),
				verifyMcpTool: vi.fn().mockResolvedValue({
					valid: true,
					pinned: false,
					firstUse: false,
				}),
			}

			mockProviderRef.deref.mockReturnValue({
				getMcpHub: () => ({
					callTool: vi.fn().mockResolvedValue(mockToolResult),
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
				schemaPinService: mockSchemaPinService,
			})

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockSchemaPinService.verifyMcpTool).toHaveBeenCalledWith({
				serverName: "test_server",
				toolName: "test_tool",
				schema: { type: "object", properties: { param: { type: "string" } } },
				signature: undefined,
				domain: "test_server",
				toolId: "test_server/test_tool",
			})
			expect(mockTask.say).toHaveBeenCalledWith("text", "✅ Schema verified for test_server/test_tool")
		})

		it("should handle schema verification failure gracefully", async () => {
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

			const mockToolResult = {
				content: [{ type: "text", text: "Tool executed successfully" }],
				isError: false,
			}

			const mockSchemaPinService = {
				initialize: vi.fn().mockResolvedValue(undefined),
				isEnabled: vi.fn().mockReturnValue(true),
				verifyMcpTool: vi.fn().mockResolvedValue({
					valid: false,
					pinned: false,
					firstUse: false,
					error: "Invalid signature",
				}),
			}

			mockProviderRef.deref.mockReturnValue({
				getMcpHub: () => ({
					callTool: vi.fn().mockResolvedValue(mockToolResult),
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
				schemaPinService: mockSchemaPinService,
			})

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.say).toHaveBeenCalledWith("text", expect.stringContaining("Schema verification failed"))
			// Tool should still execute despite verification failure
			expect(mockTask.say).toHaveBeenCalledWith("mcp_server_response", "Tool executed successfully")
		})

		it("should skip verification when SchemaPin is disabled", async () => {
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

			const mockToolResult = {
				content: [{ type: "text", text: "Tool executed successfully" }],
				isError: false,
			}

			const mockSchemaPinService = {
				initialize: vi.fn().mockResolvedValue(undefined),
				isEnabled: vi.fn().mockReturnValue(false),
				verifyMcpTool: vi.fn(),
			}

			mockProviderRef.deref.mockReturnValue({
				getMcpHub: () => ({
					callTool: vi.fn().mockResolvedValue(mockToolResult),
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
				schemaPinService: mockSchemaPinService,
			})

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockSchemaPinService.verifyMcpTool).not.toHaveBeenCalled()
			expect(mockTask.say).toHaveBeenCalledWith("mcp_server_response", "Tool executed successfully")
		})

		it("should handle first-time key pinning", async () => {
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

			const mockToolResult = {
				content: [{ type: "text", text: "Tool executed successfully" }],
				isError: false,
			}

			const mockSchemaPinService = {
				initialize: vi.fn().mockResolvedValue(undefined),
				isEnabled: vi.fn().mockReturnValue(true),
				verifyMcpTool: vi.fn().mockResolvedValue({
					valid: true,
					pinned: true,
					firstUse: true,
				}),
			}

			mockProviderRef.deref.mockReturnValue({
				getMcpHub: () => ({
					callTool: vi.fn().mockResolvedValue(mockToolResult),
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
				schemaPinService: mockSchemaPinService,
			})

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.say).toHaveBeenCalledWith(
				"text",
				"🔐 Schema verified and key pinned for test_server/test_tool",
			)
		})

		it("should continue execution when no schema is available", async () => {
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

			const mockToolResult = {
				content: [{ type: "text", text: "Tool executed successfully" }],
				isError: false,
			}

			mockProviderRef.deref.mockReturnValue({
				getMcpHub: () => ({
					callTool: vi.fn().mockResolvedValue(mockToolResult),
					getAllServers: vi.fn().mockReturnValue([
						{
							name: "test_server",
							tools: [
								{
									name: "test_tool",
									// No inputSchema provided
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
			})

			await useMcpToolTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			// Should execute tool without verification
			expect(mockTask.say).toHaveBeenCalledWith("mcp_server_response", "Tool executed successfully")
		})
	})
})
