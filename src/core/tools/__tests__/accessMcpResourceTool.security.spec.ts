/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 */
// Integration tests for accessMcpResourceTool with security validation framework

import { accessMcpResourceTool } from "../accessMcpResourceTool"
import { Task } from "../../task/Task"
import { ToolUse } from "../../../shared/tools"
import { getSecurityManager, SecurityLevel } from "../../../utils/security"

// Mock dependencies
vi.mock("../../prompts/responses", () => ({
	formatResponse: {
		toolResult: vi.fn(
			(result: string, images?: string[]) =>
				`Tool result: ${result}${images ? ` [${images.length} images]` : ""}`,
		),
		toolError: vi.fn((error: string) => `Tool error: ${error}`),
	},
}))

describe("accessMcpResourceTool - Security Integration", () => {
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
					readResource: vi.fn().mockResolvedValue({
						contents: [{ text: "Resource content retrieved successfully" }],
					}),
				}),
			}),
		}

		mockTask = {
			consecutiveMistakeCount: 0,
			recordToolError: vi.fn(),
			sayAndCreateMissingParamError: vi.fn(),
			say: vi.fn(),
			ask: vi.fn(),
			providerRef: mockProviderRef,
		}
	})

	describe("security validation", () => {
		it("should block malicious server names", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "malicious; rm -rf /",
					uri: "http://example.com/resource",
				},
				partial: false,
			}

			await accessMcpResourceTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.recordToolError).toHaveBeenCalledWith("access_mcp_resource")
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("Security violation"))
			expect(mockPushToolResult).toHaveBeenCalledWith(expect.stringContaining("Tool error:"))
		})

		it("should block malicious URIs with script injection", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "javascript:alert('xss')",
				},
				partial: false,
			}

			await accessMcpResourceTool(
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

		it("should block vbscript URIs", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "vbscript:msgbox('malicious')",
				},
				partial: false,
			}

			await accessMcpResourceTool(
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

		it("should allow safe HTTP URLs", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "http://example.com/api/resource",
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
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

		it("should allow safe HTTPS URLs", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "https://secure.example.com/api/resource",
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
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

		it("should allow file protocol URIs", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "file:///path/to/resource.txt",
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
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

		it("should allow custom protocol URIs", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "custom://protocol/resource",
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
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

		it("should sanitize and allow safe parameters", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "  test_server  ",
					uri: "  http://example.com/resource  ",
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
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

		it("should reject URIs that are too long", async () => {
			const longUri = "http://example.com/" + "a".repeat(2000)
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: longUri,
				},
				partial: false,
			}

			await accessMcpResourceTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.say).toHaveBeenCalledWith("error", expect.stringContaining("too long"))
		})

		it("should track security violations per server", async () => {
			const securityManager = getSecurityManager()

			// First violation
			const block1: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "malicious_server",
					uri: "javascript:alert(1)",
				},
				partial: false,
			}

			await accessMcpResourceTool(
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
				name: "access_mcp_resource",
				params: {
					server_name: "malicious_server",
					uri: "vbscript:msgbox(1)",
				},
				partial: false,
			}

			await accessMcpResourceTool(
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
				name: "access_mcp_resource",
				params: {
					server_name: "trusted_server",
					uri: "file:///home/user/document.txt",
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
				mockTask as Task,
				trustedBlock,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(0)
		})

		it("should handle image resources safely", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "http://example.com/image.png",
				},
				partial: false,
			}

			// Mock resource with image content
			mockProviderRef.deref.mockReturnValue({
				getMcpHub: vi.fn().mockReturnValue({
					readResource: vi.fn().mockResolvedValue({
						contents: [
							{ text: "Image metadata" },
							{ mimeType: "image/png", blob: "base64encodedimagedata" },
						],
					}),
				}),
			})

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(0)
			expect(mockTask.say).toHaveBeenCalledWith("mcp_server_response", "Image metadata", [
				"base64encodedimagedata",
			])
		})
	})

	describe("backward compatibility", () => {
		it("should maintain compatibility with existing valid calls", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "http://example.com/resource",
				},
				partial: false,
			}

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
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
			expect(mockTask.say).toHaveBeenCalledWith(
				"mcp_server_response",
				"Resource content retrieved successfully",
				[],
			)
		})

		it("should handle missing parameters with original error messages", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					uri: "http://example.com/resource",
				},
				partial: false,
			}

			mockTask.sayAndCreateMissingParamError = vi.fn().mockResolvedValue("Missing server_name error")

			await accessMcpResourceTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.consecutiveMistakeCount).toBe(1)
			expect(mockTask.recordToolError).toHaveBeenCalledWith("access_mcp_resource")
		})

		it("should handle partial requests", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "http://example.com/resource",
				},
				partial: true,
			}

			mockTask.ask = vi.fn().mockResolvedValue(true)

			await accessMcpResourceTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.ask).toHaveBeenCalledWith(
				"use_mcp_server",
				expect.stringContaining("access_mcp_resource"),
				true,
			)
		})

		it("should handle empty resource responses", async () => {
			const block: ToolUse = {
				type: "tool_use",
				name: "access_mcp_resource",
				params: {
					server_name: "test_server",
					uri: "http://example.com/empty",
				},
				partial: false,
			}

			// Mock empty resource response
			mockProviderRef.deref.mockReturnValue({
				getMcpHub: vi.fn().mockReturnValue({
					readResource: vi.fn().mockResolvedValue({
						contents: [],
					}),
				}),
			})

			mockAskApproval.mockResolvedValue(true)

			await accessMcpResourceTool(
				mockTask as Task,
				block,
				mockAskApproval,
				mockHandleError,
				mockPushToolResult,
				mockRemoveClosingTag,
			)

			expect(mockTask.say).toHaveBeenCalledWith("mcp_server_response", "(Empty response)", [])
		})
	})
})
