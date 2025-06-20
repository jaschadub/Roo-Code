import { Task } from "../task/Task"
import { ToolUse, AskApproval, HandleError, PushToolResult, RemoveClosingTag } from "../../shared/tools"
import { formatResponse } from "../prompts/responses"
import { ClineAskUseMcpServer } from "../../shared/ExtensionMessage"
import { McpExecutionStatus } from "@roo-code/types"
import { t } from "../../i18n"
import { SchemaPinService, McpToolVerificationContext } from "../../services/schemapin"
import {
	validateMcpToolParams,
	SecurityLevel,
	getSecurityManager,
	processValidationResult,
	createSecurityErrorMessage,
	sanitizeErrorMessage,
	AuditLogger,
	AuditEventType,
	AuditSeverity,
	SecurityMonitor,
	AnomalyDetector,
	type ValidationResult,
	type McpToolParams as SecureMcpToolParams,
} from "../../utils/security"

interface McpToolParams {
	server_name?: string
	tool_name?: string
	arguments?: string
}

type LegacyValidationResult =
	| { isValid: false; securityViolations?: Array<{ field: string; violation: string; severity: string }> }
	| {
			isValid: true
			serverName: string
			toolName: string
			parsedArguments?: Record<string, unknown>
	  }

async function handlePartialRequest(
	cline: Task,
	params: McpToolParams,
	removeClosingTag: RemoveClosingTag,
): Promise<void> {
	const partialMessage = JSON.stringify({
		type: "use_mcp_tool",
		serverName: removeClosingTag("server_name", params.server_name),
		toolName: removeClosingTag("tool_name", params.tool_name),
		arguments: removeClosingTag("arguments", params.arguments),
	} satisfies ClineAskUseMcpServer)

	await cline.ask("use_mcp_server", partialMessage, true).catch(() => {})
}

async function validateParams(
	cline: Task,
	params: McpToolParams,
	pushToolResult: PushToolResult,
): Promise<LegacyValidationResult> {
	// Get security manager and determine security level
	const securityManager = getSecurityManager()
	const securityLevel = params.server_name
		? securityManager.getSecurityLevelForServer(params.server_name)
		: SecurityLevel.MODERATE

	// Perform comprehensive security validation
	const validationResult = validateMcpToolParams(params, securityLevel, {
		toolName: params.tool_name,
		serverName: params.server_name,
	})

	// Process validation result through security manager
	const processedResult = processValidationResult(validationResult, params.server_name || "unknown", params.tool_name)

	if (!processedResult.success) {
		cline.consecutiveMistakeCount++
		cline.recordToolError("use_mcp_tool")

		// Handle security violations
		if (processedResult.securityViolations && processedResult.securityViolations.length > 0) {
			const errorMessage = createSecurityErrorMessage(
				processedResult.securityViolations,
				params.server_name || "unknown",
			)

			await cline.say("error", errorMessage)
			pushToolResult(formatResponse.toolError(errorMessage))

			return {
				isValid: false,
				securityViolations: processedResult.securityViolations,
			}
		}

		// Handle validation errors
		if (processedResult.errors) {
			const sanitizedError = sanitizeErrorMessage(processedResult.errors)
			await cline.say("error", sanitizedError)
			pushToolResult(formatResponse.toolError(sanitizedError))
			return { isValid: false }
		}

		// Fallback for missing parameters (backward compatibility)
		if (!params.server_name) {
			pushToolResult(await cline.sayAndCreateMissingParamError("use_mcp_tool", "server_name"))
			return { isValid: false }
		}

		if (!params.tool_name) {
			pushToolResult(await cline.sayAndCreateMissingParamError("use_mcp_tool", "tool_name"))
			return { isValid: false }
		}

		// Generic validation failure
		await cline.say("error", "Parameter validation failed")
		pushToolResult(formatResponse.toolError("Parameter validation failed"))
		return { isValid: false }
	}

	// Extract validated and sanitized parameters
	const validatedParams = processedResult.data!

	// Parse arguments if they exist
	let parsedArguments: Record<string, unknown> | undefined
	if (validatedParams.arguments !== undefined && validatedParams.arguments !== null) {
		if (typeof validatedParams.arguments === "string") {
			try {
				parsedArguments = JSON.parse(validatedParams.arguments)
			} catch {
				// If JSON parsing fails, the arguments were already sanitized as a string
				parsedArguments = { value: validatedParams.arguments }
			}
		} else {
			parsedArguments = validatedParams.arguments as Record<string, unknown>
		}
	}

	return {
		isValid: true,
		serverName: validatedParams.server_name,
		toolName: validatedParams.tool_name,
		parsedArguments,
	}
}

async function sendExecutionStatus(cline: Task, status: McpExecutionStatus): Promise<void> {
	const clineProvider = await cline.providerRef.deref()
	clineProvider?.postMessageToWebview({
		type: "mcpExecutionStatus",
		text: JSON.stringify(status),
	})
}

function processToolContent(toolResult: any): string {
	if (!toolResult?.content || toolResult.content.length === 0) {
		return ""
	}

	return toolResult.content
		.map((item: any) => {
			if (item.type === "text") {
				return item.text
			}
			if (item.type === "resource") {
				const { blob: _, ...rest } = item.resource
				return JSON.stringify(rest, null, 2)
			}
			return ""
		})
		.filter(Boolean)
		.join("\n\n")
}

async function executeToolAndProcessResult(
	cline: Task,
	serverName: string,
	toolName: string,
	parsedArguments: Record<string, unknown> | undefined,
	executionId: string,
	pushToolResult: PushToolResult,
): Promise<void> {
	await cline.say("mcp_server_request_started")

	// Send started status
	await sendExecutionStatus(cline, {
		executionId,
		status: "started",
		serverName,
		toolName,
	})

	// Perform schema verification if SchemaPin is enabled
	const provider = cline.providerRef.deref()
	const mcpHub = provider?.getMcpHub()

	if (mcpHub) {
		try {
			await performSchemaVerification(cline, serverName, toolName, mcpHub)
		} catch (verificationError) {
			// Log verification failure but continue with tool execution
			console.warn(`SchemaPin verification failed for ${serverName}/${toolName}:`, verificationError)
			await cline.say(
				"text",
				`⚠️ Schema verification failed: ${verificationError instanceof Error ? verificationError.message : String(verificationError)}`,
			)
		}
	}

	const toolResult = await mcpHub?.callTool(serverName, toolName, parsedArguments)

	let toolResultPretty = "(No response)"

	if (toolResult) {
		const outputText = processToolContent(toolResult)

		if (outputText) {
			await sendExecutionStatus(cline, {
				executionId,
				status: "output",
				response: outputText,
			})

			toolResultPretty = (toolResult.isError ? "Error:\n" : "") + outputText
		}

		// Send completion status
		await sendExecutionStatus(cline, {
			executionId,
			status: toolResult.isError ? "error" : "completed",
			response: toolResultPretty,
			error: toolResult.isError ? "Error executing MCP tool" : undefined,
		})
	} else {
		// Send error status if no result
		await sendExecutionStatus(cline, {
			executionId,
			status: "error",
			error: "No response from MCP server",
		})
	}

	await cline.say("mcp_server_response", toolResultPretty)
	pushToolResult(formatResponse.toolResult(toolResultPretty))
}

async function performSchemaVerification(
	cline: Task,
	serverName: string,
	toolName: string,
	mcpHub: any,
): Promise<void> {
	// Get SchemaPin service from provider context
	const provider = cline.providerRef.deref()
	if (!provider?.context) {
		return // No context available, skip verification
	}

	// Initialize SchemaPin service if not already done
	let schemaPinService: SchemaPinService
	try {
		// Check if SchemaPin service is already initialized in the provider
		const existingService = (provider as any).schemaPinService
		if (existingService) {
			schemaPinService = existingService
		} else {
			// Create and initialize new SchemaPin service
			schemaPinService = new SchemaPinService(provider.context, {
				enabled: true,
				verifyOnToolCall: true,
				autoPin: false, // Require user confirmation for key pinning
				pinningMode: "interactive",
			})
			await schemaPinService.initialize()

			// Store service in provider for reuse
			;(provider as any).schemaPinService = schemaPinService
		}
	} catch (error) {
		console.warn("Failed to initialize SchemaPin service:", error)
		return // Skip verification if service can't be initialized
	}

	// Skip verification if SchemaPin is disabled
	if (!schemaPinService.isEnabled()) {
		return
	}

	// Get tool schema from MCP server
	const servers = mcpHub.getAllServers()
	const server = servers.find((s: any) => s.name === serverName)
	if (!server?.tools) {
		return // No tools available, skip verification
	}

	const tool = server.tools.find((t: any) => t.name === toolName)
	if (!tool?.inputSchema) {
		return // No schema available, skip verification
	}

	// Create verification context
	const verificationContext: McpToolVerificationContext = {
		serverName,
		toolName,
		schema: tool.inputSchema,
		// Note: signature would come from the MCP server if it supports SchemaPin
		// For now, we'll handle the case where no signature is provided
		signature: undefined,
		domain: extractDomainFromServerName(serverName),
		toolId: `${serverName}/${toolName}`,
	}

	try {
		// Perform verification
		const result = await schemaPinService.verifyMcpTool(verificationContext)

		if (result.valid) {
			if (result.firstUse) {
				await cline.say("text", `🔐 Schema verified and key pinned for ${serverName}/${toolName}`)
			} else {
				await cline.say("text", `✅ Schema verified for ${serverName}/${toolName}`)
			}
		} else if (result.error) {
			// Verification failed - this is a security concern
			throw new Error(`Schema verification failed: ${result.error}`)
		}
	} catch (error) {
		// Re-throw verification errors to be handled by caller
		throw error
	}
}

function extractDomainFromServerName(serverName: string): string {
	// Try to extract domain from server name
	const urlMatch = serverName.match(/https?:\/\/([^\/]+)/)
	if (urlMatch) {
		return urlMatch[1]
	}

	// Check if it looks like a domain
	if (serverName.includes(".") && !serverName.includes("/")) {
		return serverName
	}

	// Fallback to using the server name as domain
	return serverName
}

export async function useMcpToolTool(
	cline: Task,
	block: ToolUse,
	askApproval: AskApproval,
	handleError: HandleError,
	pushToolResult: PushToolResult,
	removeClosingTag: RemoveClosingTag,
) {
	try {
		const params: McpToolParams = {
			server_name: block.params.server_name,
			tool_name: block.params.tool_name,
			arguments: block.params.arguments,
		}

		// Handle partial requests
		if (block.partial) {
			await handlePartialRequest(cline, params, removeClosingTag)
			return
		}

		// Validate parameters
		const validation = await validateParams(cline, params, pushToolResult)
		if (!validation.isValid) {
			return
		}

		const { serverName, toolName, parsedArguments } = validation

		// Reset mistake count on successful validation
		cline.consecutiveMistakeCount = 0

		// Get user approval
		const completeMessage = JSON.stringify({
			type: "use_mcp_tool",
			serverName,
			toolName,
			arguments: params.arguments,
		} satisfies ClineAskUseMcpServer)

		const executionId = cline.lastMessageTs?.toString() ?? Date.now().toString()
		const didApprove = await askApproval("use_mcp_server", completeMessage)

		if (!didApprove) {
			return
		}

		// Execute the tool and process results
		await executeToolAndProcessResult(cline, serverName!, toolName!, parsedArguments, executionId, pushToolResult)
	} catch (error) {
		await handleError("executing MCP tool", error)
	}
}
