import { ClineAskUseMcpServer } from "../../shared/ExtensionMessage"
import { ToolUse, RemoveClosingTag, AskApproval, HandleError, PushToolResult } from "../../shared/tools"
import { Task } from "../task/Task"
import { formatResponse } from "../prompts/responses"
import {
	validateMcpResourceParams,
	SecurityLevel,
	getSecurityManager,
	processValidationResult,
	createSecurityErrorMessage,
	sanitizeErrorMessage,
} from "../../utils/security"

export async function accessMcpResourceTool(
	cline: Task,
	block: ToolUse,
	askApproval: AskApproval,
	handleError: HandleError,
	pushToolResult: PushToolResult,
	removeClosingTag: RemoveClosingTag,
) {
	const server_name: string | undefined = block.params.server_name
	const uri: string | undefined = block.params.uri

	try {
		if (block.partial) {
			const partialMessage = JSON.stringify({
				type: "access_mcp_resource",
				serverName: removeClosingTag("server_name", server_name),
				uri: removeClosingTag("uri", uri),
			} satisfies ClineAskUseMcpServer)

			await cline.ask("use_mcp_server", partialMessage, block.partial).catch(() => {})
			return
		}

		// Perform comprehensive security validation
		const securityManager = getSecurityManager()
		const securityLevel = server_name
			? securityManager.getSecurityLevelForServer(server_name)
			: SecurityLevel.MODERATE

		const validationResult = validateMcpResourceParams({ server_name, uri }, securityLevel, {
			serverName: server_name,
		})

		// Process validation result through security manager
		const processedResult = processValidationResult(validationResult, server_name || "unknown")

		if (!processedResult.success) {
			cline.consecutiveMistakeCount++
			cline.recordToolError("access_mcp_resource")

			// Handle security violations
			if (processedResult.securityViolations && processedResult.securityViolations.length > 0) {
				const errorMessage = createSecurityErrorMessage(
					processedResult.securityViolations,
					server_name || "unknown",
				)

				await cline.say("error", errorMessage)
				pushToolResult(formatResponse.toolError(errorMessage))
				return
			}

			// Handle validation errors
			if (processedResult.errors) {
				const sanitizedError = sanitizeErrorMessage(processedResult.errors)
				await cline.say("error", sanitizedError)
				pushToolResult(formatResponse.toolError(sanitizedError))
				return
			}

			// Fallback for missing parameters (backward compatibility)
			if (!server_name) {
				pushToolResult(await cline.sayAndCreateMissingParamError("access_mcp_resource", "server_name"))
				return
			}

			if (!uri) {
				pushToolResult(await cline.sayAndCreateMissingParamError("access_mcp_resource", "uri"))
				return
			}

			// Generic validation failure
			await cline.say("error", "Parameter validation failed")
			pushToolResult(formatResponse.toolError("Parameter validation failed"))
			return
		}

		// Extract validated and sanitized parameters
		const validatedParams = processedResult.data!
		const validatedServerName = validatedParams.server_name
		const validatedUri = validatedParams.uri

		cline.consecutiveMistakeCount = 0

		const completeMessage = JSON.stringify({
			type: "access_mcp_resource",
			serverName: validatedServerName,
			uri: validatedUri,
		} satisfies ClineAskUseMcpServer)

		const didApprove = await askApproval("use_mcp_server", completeMessage)

		if (!didApprove) {
			return
		}

		// Now execute the tool with validated parameters
		await cline.say("mcp_server_request_started")
		const resourceResult = await cline.providerRef
			.deref()
			?.getMcpHub()
			?.readResource(validatedServerName, validatedUri)

		const resourceResultPretty =
			resourceResult?.contents
				.map((item) => {
					if (item.text) {
						return item.text
					}
					return ""
				})
				.filter(Boolean)
				.join("\n\n") || "(Empty response)"

		// Handle images (image must contain mimetype and blob)
		let images: string[] = []

		resourceResult?.contents.forEach((item) => {
			if (item.mimeType?.startsWith("image") && item.blob) {
				images.push(item.blob)
			}
		})

		await cline.say("mcp_server_response", resourceResultPretty, images)
		pushToolResult(formatResponse.toolResult(resourceResultPretty, images))
	} catch (error) {
		await handleError("accessing MCP resource", error)
	}
}
