/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Security-focused input sanitization utilities for MCP tool parameters.
 * Provides protection against command injection, XSS, and data exfiltration attacks.
 */

import { z } from "zod"

/**
 * Configuration for input sanitization behavior
 */
export interface SanitizationConfig {
	/** Maximum string length allowed */
	maxStringLength: number
	/** Maximum object depth allowed */
	maxObjectDepth: number
	/** Maximum number of properties in an object */
	maxObjectProperties: number
	/** Maximum array length allowed */
	maxArrayLength: number
	/** Whether to allow file paths */
	allowFilePaths: boolean
	/** Whether to allow URLs */
	allowUrls: boolean
	/** Whether to allow shell commands */
	allowShellCommands: boolean
	/** Custom blocked patterns (regex strings) */
	blockedPatterns: string[]
}

/**
 * Default sanitization configuration with security-first defaults
 */
export const DEFAULT_SANITIZATION_CONFIG: SanitizationConfig = {
	maxStringLength: 10000,
	maxObjectDepth: 10,
	maxObjectProperties: 100,
	maxArrayLength: 1000,
	allowFilePaths: false,
	allowUrls: false,
	allowShellCommands: false,
	blockedPatterns: [
		// Command injection patterns
		"[;&|`$(){}\\[\\]]",
		// SQL injection patterns
		"(union|select|insert|update|delete|drop|create|alter)\\s",
		// Script injection patterns
		"<script[^>]*>",
		"javascript:",
		"vbscript:",
		// Path traversal patterns
		"\\.\\./",
		"\\.\\.\\\\",
		// Null bytes and control characters
		"\\x00-\\x1f",
		"\\x7f-\\x9f",
	],
}

/**
 * Security validation error with detailed context
 */
export class SecurityValidationError extends Error {
	constructor(
		message: string,
		public readonly field: string,
		public readonly value: unknown,
		public readonly violationType: string,
	) {
		super(message)
		this.name = "SecurityValidationError"
	}
}

/**
 * Sanitizes a string value according to security policies
 */
export function sanitizeString(
	value: string,
	field: string,
	config: SanitizationConfig = DEFAULT_SANITIZATION_CONFIG,
): string {
	// Check length limits
	if (value.length > config.maxStringLength) {
		throw new SecurityValidationError(
			`String exceeds maximum length of ${config.maxStringLength}`,
			field,
			value,
			"length_violation",
		)
	}

	// Check for blocked patterns
	for (const pattern of config.blockedPatterns) {
		const regex = new RegExp(pattern, "gi")
		if (regex.test(value)) {
			throw new SecurityValidationError(
				`String contains blocked pattern: ${pattern}`,
				field,
				value,
				"pattern_violation",
			)
		}
	}

	// Check file path restrictions
	if (!config.allowFilePaths && isFilePath(value)) {
		throw new SecurityValidationError(
			"File paths are not allowed in this context",
			field,
			value,
			"filepath_violation",
		)
	}

	// Check URL restrictions
	if (!config.allowUrls && isUrl(value)) {
		throw new SecurityValidationError("URLs are not allowed in this context", field, value, "url_violation")
	}

	// Check shell command restrictions
	if (!config.allowShellCommands && isShellCommand(value)) {
		throw new SecurityValidationError(
			"Shell commands are not allowed in this context",
			field,
			value,
			"shell_violation",
		)
	}

	// Remove null bytes and normalize whitespace
	return value.replace(/\0/g, "").trim()
}

/**
 * Sanitizes an object recursively with depth and property limits
 */
export function sanitizeObject(
	value: Record<string, unknown>,
	field: string,
	config: SanitizationConfig = DEFAULT_SANITIZATION_CONFIG,
	currentDepth: number = 0,
): Record<string, unknown> {
	// Check depth limits
	if (currentDepth > config.maxObjectDepth) {
		throw new SecurityValidationError(
			`Object exceeds maximum depth of ${config.maxObjectDepth}`,
			field,
			value,
			"depth_violation",
		)
	}

	// Check property count limits
	const propertyCount = Object.keys(value).length
	if (propertyCount > config.maxObjectProperties) {
		throw new SecurityValidationError(
			`Object exceeds maximum properties of ${config.maxObjectProperties}`,
			field,
			value,
			"property_count_violation",
		)
	}

	const sanitized: Record<string, unknown> = {}

	for (const [key, val] of Object.entries(value)) {
		// Sanitize the key itself
		const sanitizedKey = sanitizeString(key, `${field}.${key}`, config)

		// Recursively sanitize the value
		sanitized[sanitizedKey] = sanitizeValue(val, `${field}.${key}`, config, currentDepth + 1)
	}

	return sanitized
}

/**
 * Sanitizes an array with length limits
 */
export function sanitizeArray(
	value: unknown[],
	field: string,
	config: SanitizationConfig = DEFAULT_SANITIZATION_CONFIG,
	currentDepth: number = 0,
): unknown[] {
	// Check array length limits
	if (value.length > config.maxArrayLength) {
		throw new SecurityValidationError(
			`Array exceeds maximum length of ${config.maxArrayLength}`,
			field,
			value,
			"array_length_violation",
		)
	}

	return value.map((item, index) => sanitizeValue(item, `${field}[${index}]`, config, currentDepth + 1))
}

/**
 * Sanitizes any value based on its type
 */
export function sanitizeValue(
	value: unknown,
	field: string,
	config: SanitizationConfig = DEFAULT_SANITIZATION_CONFIG,
	currentDepth: number = 0,
): unknown {
	if (value === null || value === undefined) {
		return value
	}

	if (typeof value === "string") {
		return sanitizeString(value, field, config)
	}

	if (typeof value === "number" || typeof value === "boolean") {
		return value
	}

	if (Array.isArray(value)) {
		return sanitizeArray(value, field, config, currentDepth)
	}

	if (typeof value === "object") {
		return sanitizeObject(value as Record<string, unknown>, field, config, currentDepth)
	}

	// For any other type, convert to string and sanitize
	return sanitizeString(String(value), field, config)
}

/**
 * Checks if a string appears to be a file path
 */
function isFilePath(value: string): boolean {
	// Don't treat simple names with dots as file paths (like server.example)
	if (/^[a-zA-Z0-9._-]+$/.test(value) && !value.includes("/") && !value.includes("\\")) {
		// Only consider it a file path if it has a clear file extension at the end
		if (/\.[a-zA-Z0-9]{1,10}$/.test(value)) {
			// But exclude common server/domain patterns
			if (/^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+$/.test(value)) {
				return false // This looks like a domain or server name
			}
		} else {
			return false // No file extension, probably not a file path
		}
	}

	// Common file path patterns
	const filePathPatterns = [
		/^[a-zA-Z]:[\\\/]/, // Windows absolute path
		/^\//, // Unix absolute path
		/^\.\.?[\/\\]/, // Relative path with .. or .
		/[\/\\]/, // Contains path separators
	]

	return filePathPatterns.some((pattern) => pattern.test(value))
}

/**
 * Checks if a string appears to be a URL
 */
function isUrl(value: string): boolean {
	try {
		new URL(value)
		return true
	} catch {
		// Also check for protocol-relative URLs and common URL patterns
		const urlPatterns = [
			/^\/\//, // Protocol-relative URL
			/^https?:\/\//, // HTTP/HTTPS
			/^ftp:\/\//, // FTP
			/^file:\/\//, // File protocol
			/^[a-z][a-z0-9+.-]*:/, // Any protocol
		]

		return urlPatterns.some((pattern) => pattern.test(value.toLowerCase()))
	}
}

/**
 * Checks if a string appears to be a shell command
 */
function isShellCommand(value: string): boolean {
	const shellPatterns = [
		/^(sudo|su|chmod|chown|rm|mv|cp|cat|grep|awk|sed|find|exec|eval|source|\.)(\s|$)/, // Common shell commands
		/[;&|`$(){}]/, // Shell metacharacters
		/\$\{[^}]*\}/, // Variable expansion
		/\$\([^)]*\)/, // Command substitution
		/`[^`]*`/, // Backtick command substitution
	]

	return shellPatterns.some((pattern) => pattern.test(value))
}

/**
 * Creates a custom sanitization configuration for specific use cases
 */
export function createSanitizationConfig(overrides: Partial<SanitizationConfig>): SanitizationConfig {
	return {
		...DEFAULT_SANITIZATION_CONFIG,
		...overrides,
	}
}

/**
 * Validates that a sanitized value meets security requirements
 */
export function validateSanitizedValue(value: unknown, field: string): void {
	// Additional post-sanitization validation can be added here
	// For now, we trust that the sanitization process has handled security concerns

	// Check for any remaining suspicious patterns that might have been missed
	if (typeof value === "string") {
		// Check for encoded injection attempts
		const suspiciousEncodedPatterns = [
			/%[0-9a-f]{2}/gi, // URL encoding
			/&#[0-9]+;/gi, // HTML entity encoding
			/\\x[0-9a-f]{2}/gi, // Hex encoding
			/\\u[0-9a-f]{4}/gi, // Unicode encoding
		]

		for (const pattern of suspiciousEncodedPatterns) {
			if (pattern.test(value)) {
				throw new SecurityValidationError(
					"Potentially encoded malicious content detected",
					field,
					value,
					"encoded_content_violation",
				)
			}
		}
	}
}
