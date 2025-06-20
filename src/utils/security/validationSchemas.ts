/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Zod schemas for validating MCP tool parameters with security-focused constraints.
 * These schemas provide comprehensive validation and sanitization for all MCP tool inputs.
 */

import { z } from "zod"
import { sanitizeValue, createSanitizationConfig, SanitizationConfig } from "./inputSanitizer"

/**
 * Security levels for different validation contexts
 */
export enum SecurityLevel {
	STRICT = "strict",
	MODERATE = "moderate",
	PERMISSIVE = "permissive",
}

/**
 * Security configuration mapping for different security levels
 */
const SECURITY_CONFIGS: Record<SecurityLevel, SanitizationConfig> = {
	[SecurityLevel.STRICT]: createSanitizationConfig({
		maxStringLength: 1000,
		maxObjectDepth: 5,
		maxObjectProperties: 20,
		maxArrayLength: 100,
		allowFilePaths: false,
		allowUrls: false,
		allowShellCommands: false,
	}),
	[SecurityLevel.MODERATE]: createSanitizationConfig({
		maxStringLength: 5000,
		maxObjectDepth: 8,
		maxObjectProperties: 50,
		maxArrayLength: 500,
		allowFilePaths: true,
		allowUrls: true,
		allowShellCommands: false,
	}),
	[SecurityLevel.PERMISSIVE]: createSanitizationConfig({
		maxStringLength: 10000,
		maxObjectDepth: 10,
		maxObjectProperties: 100,
		maxArrayLength: 1000,
		allowFilePaths: true,
		allowUrls: true,
		allowShellCommands: true,
	}),
}

/**
 * Creates a sanitizing string schema with security validation
 */
function createSecureStringSchema(securityLevel: SecurityLevel = SecurityLevel.MODERATE, fieldName: string = "string") {
	return z
		.string()
		.transform((value) => {
			const config = SECURITY_CONFIGS[securityLevel]
			return sanitizeValue(value, fieldName, config) as string
		})
		.refine(
			(value) => {
				// Additional validation after sanitization
				return typeof value === "string" && value.length > 0
			},
			{
				message: "String must not be empty after sanitization",
			},
		)
}

/**
 * Creates a sanitizing object schema with security validation
 */
function createSecureObjectSchema(securityLevel: SecurityLevel = SecurityLevel.MODERATE, fieldName: string = "object") {
	return z
		.record(z.unknown())
		.transform((value) => {
			const config = SECURITY_CONFIGS[securityLevel]
			return sanitizeValue(value, fieldName, config) as Record<string, unknown>
		})
		.refine(
			(value) => {
				// Additional validation after sanitization
				return typeof value === "object" && value !== null
			},
			{
				message: "Must be a valid object after sanitization",
			},
		)
}

/**
 * Server name validation schema with strict security
 */
export const serverNameSchema = z
	.string()
	.min(1, "Server name is required")
	.max(100, "Server name too long")
	.transform((value) => {
		// First sanitize (trim whitespace)
		const trimmed = value.trim()

		// Then validate format
		if (!/^[a-zA-Z0-9._-]+$/.test(trimmed)) {
			throw new Error("Server name contains invalid characters")
		}

		const config = createSanitizationConfig({
			maxStringLength: 100,
			allowFilePaths: false,
			allowUrls: false,
			allowShellCommands: false,
			blockedPatterns: [
				// Remove the generic pattern that conflicts with valid server names
				"[;&|`$(){}\\[\\]]",
				"(union|select|insert|update|delete|drop|create|alter)\\s",
				"<script[^>]*>",
				"javascript:",
				"vbscript:",
				"\\.\\./",
				"\\.\\.\\\\",
				"\\x00-\\x1f",
				"\\x7f-\\x9f",
			],
		})
		return sanitizeValue(trimmed, "server_name", config) as string
	})

/**
 * Tool name validation schema with strict security
 */
export const toolNameSchema = z
	.string()
	.min(1, "Tool name is required")
	.max(100, "Tool name too long")
	.transform((value) => {
		// First sanitize (trim whitespace)
		const trimmed = value.trim()

		// Then validate format
		if (!/^[a-zA-Z0-9._-]+$/.test(trimmed)) {
			throw new Error("Tool name contains invalid characters")
		}

		const config = createSanitizationConfig({
			maxStringLength: 100,
			allowFilePaths: false,
			allowUrls: false,
			allowShellCommands: false,
			blockedPatterns: [
				// Remove the generic pattern that conflicts with valid tool names
				"[;&|`$(){}\\[\\]]",
				"(union|select|insert|update|delete|drop|create|alter)\\s",
				"<script[^>]*>",
				"javascript:",
				"vbscript:",
				"\\.\\./",
				"\\.\\.\\\\",
				"\\x00-\\x1f",
				"\\x7f-\\x9f",
			],
		})
		return sanitizeValue(trimmed, "tool_name", config) as string
	})

/**
 * URI validation schema for resource access with moderate security
 */
export const uriSchema = z
	.string()
	.min(1, "URI is required")
	.max(2000, "URI too long")
	.transform((value) => {
		const config = createSanitizationConfig({
			maxStringLength: 2000,
			allowFilePaths: true,
			allowUrls: true,
			allowShellCommands: false,
			blockedPatterns: [
				// Remove shell command patterns but keep URL/file patterns
				"[;&|`$(){}\\[\\]]",
				"(union|select|insert|update|delete|drop|create|alter)\\s",
				"<script[^>]*>",
				"javascript:",
				"vbscript:",
				"\\x00-\\x1f",
				"\\x7f-\\x9f",
			],
		})
		return sanitizeValue(value, "uri", config) as string
	})
	.refine(
		(value) => {
			// Validate URI format
			try {
				// Check if it's a valid URL
				new URL(value)
				return true
			} catch {
				// Check if it's a valid URI scheme
				return /^[a-z][a-z0-9+.-]*:/i.test(value) || /^[a-zA-Z0-9._/-]+$/.test(value)
			}
		},
		{
			message: "Invalid URI format",
		},
	)

/**
 * Tool arguments validation schema with configurable security level
 */
export function createToolArgumentsSchema(securityLevel: SecurityLevel = SecurityLevel.MODERATE) {
	return z
		.union([z.string(), z.record(z.unknown()), z.array(z.unknown()), z.null(), z.undefined()])
		.transform((value) => {
			if (value === null || value === undefined) {
				return value
			}

			// If it's a string, try to parse as JSON first
			if (typeof value === "string") {
				try {
					const parsed = JSON.parse(value)
					const config = SECURITY_CONFIGS[securityLevel]
					return sanitizeValue(parsed, "arguments", config)
				} catch {
					// If JSON parsing fails, treat as plain string
					const config = SECURITY_CONFIGS[securityLevel]
					return sanitizeValue(value, "arguments", config)
				}
			}

			// For objects and arrays, sanitize directly
			const config = SECURITY_CONFIGS[securityLevel]
			return sanitizeValue(value, "arguments", config)
		})
		.refine(
			(value) => {
				// Validate that the sanitized value is safe
				if (value === null || value === undefined) {
					return true
				}

				// Check for reasonable size limits
				const serialized = JSON.stringify(value)
				return serialized.length <= 50000 // 50KB limit
			},
			{
				message: "Arguments too large after sanitization",
			},
		)
}

/**
 * Complete MCP tool parameters validation schema
 */
export function createMcpToolParamsSchema(securityLevel: SecurityLevel = SecurityLevel.MODERATE) {
	return z.object({
		server_name: serverNameSchema,
		tool_name: toolNameSchema,
		arguments: createToolArgumentsSchema(securityLevel).optional(),
	})
}

/**
 * Complete MCP resource parameters validation schema
 */
export function createMcpResourceParamsSchema(securityLevel: SecurityLevel = SecurityLevel.MODERATE) {
	return z.object({
		server_name: serverNameSchema,
		uri: uriSchema,
	})
}

/**
 * Validation context for tracking validation metadata
 */
export interface ValidationContext {
	securityLevel: SecurityLevel
	toolName?: string
	serverName?: string
	timestamp: number
	userAgent?: string
}

/**
 * Validation result with detailed information
 */
export interface ValidationResult<T> {
	success: boolean
	data?: T
	errors?: z.ZodError
	securityViolations?: Array<{
		field: string
		violation: string
		severity: "low" | "medium" | "high"
	}>
	context: ValidationContext
}

/**
 * Validates MCP tool parameters with comprehensive error handling
 */
export function validateMcpToolParams(
	params: unknown,
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
	context: Partial<ValidationContext> = {},
): ValidationResult<z.infer<ReturnType<typeof createMcpToolParamsSchema>>> {
	const validationContext: ValidationContext = {
		securityLevel,
		timestamp: Date.now(),
		...context,
	}

	try {
		const schema = createMcpToolParamsSchema(securityLevel)
		const result = schema.parse(params)

		return {
			success: true,
			data: result,
			context: validationContext,
		}
	} catch (error) {
		if (error instanceof z.ZodError) {
			// Extract security violations from Zod errors
			const securityViolations = error.issues
				.filter((issue) => issue.message.includes("security") || issue.message.includes("blocked"))
				.map((issue) => ({
					field: issue.path.join("."),
					violation: issue.message,
					severity: "high" as const,
				}))

			return {
				success: false,
				errors: error,
				securityViolations,
				context: validationContext,
			}
		}

		// Handle other types of errors
		return {
			success: false,
			securityViolations: [
				{
					field: "unknown",
					violation: error instanceof Error ? error.message : "Unknown validation error",
					severity: "medium",
				},
			],
			context: validationContext,
		}
	}
}

/**
 * Validates MCP resource parameters with comprehensive error handling
 */
export function validateMcpResourceParams(
	params: unknown,
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
	context: Partial<ValidationContext> = {},
): ValidationResult<z.infer<ReturnType<typeof createMcpResourceParamsSchema>>> {
	const validationContext: ValidationContext = {
		securityLevel,
		timestamp: Date.now(),
		...context,
	}

	try {
		const schema = createMcpResourceParamsSchema(securityLevel)
		const result = schema.parse(params)

		return {
			success: true,
			data: result,
			context: validationContext,
		}
	} catch (error) {
		if (error instanceof z.ZodError) {
			// Extract security violations from Zod errors
			const securityViolations = error.issues
				.filter((issue) => issue.message.includes("security") || issue.message.includes("blocked"))
				.map((issue) => ({
					field: issue.path.join("."),
					violation: issue.message,
					severity: "high" as const,
				}))

			return {
				success: false,
				errors: error,
				securityViolations,
				context: validationContext,
			}
		}

		// Handle other types of errors
		return {
			success: false,
			securityViolations: [
				{
					field: "unknown",
					violation: error instanceof Error ? error.message : "Unknown validation error",
					severity: "medium",
				},
			],
			context: validationContext,
		}
	}
}

/**
 * Type exports for external use
 */
export type McpToolParams = z.infer<ReturnType<typeof createMcpToolParamsSchema>>
export type McpResourceParams = z.infer<ReturnType<typeof createMcpResourceParamsSchema>>
