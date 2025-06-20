/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Secure path validation and normalization utilities for MCP server operations.
 * Provides protection against path traversal and directory injection attacks.
 */

import * as path from "path"
import { z } from "zod"
import { SecurityLevel } from "./validationSchemas"

/**
 * Path validation configuration
 */
export interface PathSecurityConfig {
	/** Security level for path validation */
	securityLevel: SecurityLevel
	/** Allowed base directories */
	allowedBasePaths: string[]
	/** Blocked directories */
	blockedPaths: string[]
	/** Whether to allow relative paths */
	allowRelativePaths: boolean
	/** Whether to allow absolute paths */
	allowAbsolutePaths: boolean
	/** Whether to allow symlinks */
	allowSymlinks: boolean
	/** Maximum path length */
	maxPathLength: number
	/** Allowed file extensions */
	allowedExtensions: string[]
	/** Blocked file extensions */
	blockedExtensions: string[]
}

/**
 * Path validation result
 */
export interface PathValidationResult {
	isValid: boolean
	normalizedPath: string
	violations: Array<{
		type: string
		message: string
		severity: "low" | "medium" | "high"
	}>
	metadata: {
		isAbsolute: boolean
		isRelative: boolean
		extension: string | null
		depth: number
		containsTraversal: boolean
	}
}

/**
 * Default path security configurations by security level
 */
const DEFAULT_PATH_CONFIGS: Record<SecurityLevel, PathSecurityConfig> = {
	[SecurityLevel.STRICT]: {
		securityLevel: SecurityLevel.STRICT,
		allowedBasePaths: [],
		blockedPaths: [
			"/etc",
			"/usr",
			"/bin",
			"/sbin",
			"/boot",
			"/dev",
			"/proc",
			"/sys",
			"/System",
			"/Windows",
			"/Program Files",
			"/Program Files (x86)",
			"C:\\Windows",
			"C:\\Program Files",
			"C:\\Program Files (x86)",
		],
		allowRelativePaths: true,
		allowAbsolutePaths: false,
		allowSymlinks: false,
		maxPathLength: 260, // Windows MAX_PATH
		allowedExtensions: [".js", ".mjs", ".py", ".json", ".txt", ".md"],
		blockedExtensions: [".exe", ".bat", ".cmd", ".ps1", ".sh", ".dll", ".so"],
	},
	[SecurityLevel.MODERATE]: {
		securityLevel: SecurityLevel.MODERATE,
		allowedBasePaths: [],
		blockedPaths: [
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/System/Library",
			"/Windows/System32",
			"C:\\Windows\\System32",
			"C:\\Windows\\SysWOW64",
		],
		allowRelativePaths: true,
		allowAbsolutePaths: true,
		allowSymlinks: false,
		maxPathLength: 1024,
		allowedExtensions: [],
		blockedExtensions: [".exe", ".bat", ".cmd", ".ps1", ".dll", ".so"],
	},
	[SecurityLevel.PERMISSIVE]: {
		securityLevel: SecurityLevel.PERMISSIVE,
		allowedBasePaths: [],
		blockedPaths: [],
		allowRelativePaths: true,
		allowAbsolutePaths: true,
		allowSymlinks: true,
		maxPathLength: 4096,
		allowedExtensions: [],
		blockedExtensions: [],
	},
}

/**
 * Path security error
 */
export class PathSecurityError extends Error {
	constructor(
		message: string,
		public readonly violations: PathValidationResult["violations"],
		public readonly path: string,
	) {
		super(message)
		this.name = "PathSecurityError"
	}
}

/**
 * Validates and normalizes a file path for secure access
 */
export function validatePath(
	inputPath: string,
	config?: Partial<PathSecurityConfig>,
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
): PathValidationResult {
	const pathConfig = {
		...DEFAULT_PATH_CONFIGS[securityLevel],
		...config,
	}

	const result: PathValidationResult = {
		isValid: true,
		normalizedPath: "",
		violations: [],
		metadata: {
			isAbsolute: false,
			isRelative: false,
			extension: null,
			depth: 0,
			containsTraversal: false,
		},
	}

	try {
		// Basic validation
		if (!inputPath || typeof inputPath !== "string") {
			result.violations.push({
				type: "invalid_input",
				message: "Path must be a non-empty string",
				severity: "high",
			})
			result.isValid = false
			return result
		}

		// Check path length
		if (inputPath.length > pathConfig.maxPathLength) {
			result.violations.push({
				type: "path_too_long",
				message: `Path exceeds maximum length of ${pathConfig.maxPathLength}`,
				severity: "medium",
			})
		}

		// Normalize the path
		const normalizedPath = normalizePath(inputPath)
		result.normalizedPath = normalizedPath

		// Analyze path metadata
		result.metadata.isAbsolute = path.isAbsolute(normalizedPath)
		result.metadata.isRelative = !result.metadata.isAbsolute
		result.metadata.extension = getFileExtension(normalizedPath)
		result.metadata.depth = getPathDepth(normalizedPath)
		result.metadata.containsTraversal = containsPathTraversal(inputPath)

		// Check for path traversal
		if (result.metadata.containsTraversal) {
			result.violations.push({
				type: "path_traversal",
				message: "Path contains traversal sequences (..)",
				severity: "high",
			})
		}

		// Check absolute/relative path restrictions
		if (result.metadata.isAbsolute && !pathConfig.allowAbsolutePaths) {
			result.violations.push({
				type: "absolute_path_blocked",
				message: "Absolute paths are not allowed",
				severity: "medium",
			})
		}

		if (result.metadata.isRelative && !pathConfig.allowRelativePaths) {
			result.violations.push({
				type: "relative_path_blocked",
				message: "Relative paths are not allowed",
				severity: "medium",
			})
		}

		// Check allowed base paths
		if (pathConfig.allowedBasePaths.length > 0) {
			const isInAllowedPath = pathConfig.allowedBasePaths.some((basePath) =>
				isPathUnder(normalizedPath, basePath),
			)
			if (!isInAllowedPath) {
				result.violations.push({
					type: "path_not_allowed",
					message: "Path is not under any allowed base directory",
					severity: "high",
				})
			}
		}

		// Check blocked paths
		for (const blockedPath of pathConfig.blockedPaths) {
			if (isPathUnder(normalizedPath, blockedPath) || normalizedPath === normalizePath(blockedPath)) {
				result.violations.push({
					type: "path_blocked",
					message: `Path is under blocked directory: ${blockedPath}`,
					severity: "high",
				})
			}
		}

		// Check file extensions
		if (result.metadata.extension) {
			if (
				pathConfig.allowedExtensions.length > 0 &&
				!pathConfig.allowedExtensions.includes(result.metadata.extension)
			) {
				result.violations.push({
					type: "extension_not_allowed",
					message: `File extension '${result.metadata.extension}' is not allowed`,
					severity: "medium",
				})
			}

			if (pathConfig.blockedExtensions.includes(result.metadata.extension)) {
				result.violations.push({
					type: "extension_blocked",
					message: `File extension '${result.metadata.extension}' is blocked`,
					severity: "high",
				})
			}
		}

		// Check for dangerous patterns
		const dangerousPatterns = [
			/\0/, // Null bytes
			/[\x00-\x1f\x7f-\x9f]/, // Control characters
			/[<>:"|?*]/, // Windows reserved characters
			/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i, // Windows reserved names
		]

		for (const pattern of dangerousPatterns) {
			if (pattern.test(normalizedPath)) {
				result.violations.push({
					type: "dangerous_pattern",
					message: "Path contains dangerous characters or patterns",
					severity: "high",
				})
				break
			}
		}

		// Set overall validity
		result.isValid = result.violations.length === 0 || !result.violations.some((v) => v.severity === "high")
	} catch (error) {
		result.violations.push({
			type: "validation_error",
			message: error instanceof Error ? error.message : "Unknown validation error",
			severity: "high",
		})
		result.isValid = false
	}

	return result
}

/**
 * Validates a working directory path
 */
export function validateWorkingDirectory(
	workingDir: string,
	allowedDirectories: string[] = [],
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
): PathValidationResult {
	const config = {
		...DEFAULT_PATH_CONFIGS[securityLevel],
		allowedBasePaths: allowedDirectories,
	}

	const result = validatePath(workingDir, config, securityLevel)

	// Additional checks for working directories
	if (result.metadata.extension) {
		result.violations.push({
			type: "directory_has_extension",
			message: "Working directory path should not have a file extension",
			severity: "medium",
		})
	}

	return result
}

/**
 * Securely resolves a path relative to a base directory
 */
export function securePathResolve(
	basePath: string,
	relativePath: string,
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
): string {
	// Validate base path
	const baseValidation = validatePath(basePath, undefined, securityLevel)
	if (!baseValidation.isValid) {
		throw new PathSecurityError("Invalid base path", baseValidation.violations, basePath)
	}

	// Validate relative path
	const relativeValidation = validatePath(relativePath, undefined, securityLevel)
	if (!relativeValidation.isValid) {
		throw new PathSecurityError("Invalid relative path", relativeValidation.violations, relativePath)
	}

	// Resolve the path
	const resolvedPath = path.resolve(baseValidation.normalizedPath, relativeValidation.normalizedPath)

	// Ensure the resolved path is still under the base path
	if (!isPathUnder(resolvedPath, baseValidation.normalizedPath)) {
		throw new PathSecurityError(
			"Resolved path escapes base directory",
			[
				{
					type: "path_escape",
					message: "Path resolution would escape the base directory",
					severity: "high",
				},
			],
			resolvedPath,
		)
	}

	return resolvedPath
}

/**
 * Helper functions
 */

function normalizePath(inputPath: string): string {
	// Normalize path separators and resolve relative components
	let normalized = inputPath.replace(/[\\\/]+/g, path.sep)

	// Use path.normalize to handle . and .. components
	normalized = path.normalize(normalized)

	// Remove trailing separators except for root
	if (normalized.length > 1 && normalized.endsWith(path.sep)) {
		normalized = normalized.slice(0, -1)
	}

	return normalized
}

function getFileExtension(filePath: string): string | null {
	const ext = path.extname(filePath)
	return ext || null
}

function getPathDepth(filePath: string): number {
	const normalized = normalizePath(filePath)
	const parts = normalized.split(path.sep).filter((part) => part.length > 0)
	return parts.length
}

function containsPathTraversal(inputPath: string): boolean {
	// Check for various path traversal patterns
	const traversalPatterns = [
		/\.\./, // Standard traversal
		/%2e%2e/i, // URL encoded
		/%252e%252e/i, // Double URL encoded
		/\.\%2f/i, // Mixed encoding
		/\%2e\./i, // Mixed encoding
	]

	return traversalPatterns.some((pattern) => pattern.test(inputPath))
}

function isPathUnder(childPath: string, parentPath: string): boolean {
	const normalizedChild = normalizePath(childPath)
	const normalizedParent = normalizePath(parentPath)

	// Make paths absolute for comparison
	const absoluteChild = path.resolve(normalizedChild)
	const absoluteParent = path.resolve(normalizedParent)

	// Check if child path starts with parent path
	return absoluteChild.startsWith(absoluteParent + path.sep) || absoluteChild === absoluteParent
}

/**
 * Zod schema for path security configuration
 */
export const PathSecurityConfigSchema = z.object({
	securityLevel: z.nativeEnum(SecurityLevel),
	allowedBasePaths: z.array(z.string()),
	blockedPaths: z.array(z.string()),
	allowRelativePaths: z.boolean(),
	allowAbsolutePaths: z.boolean(),
	allowSymlinks: z.boolean(),
	maxPathLength: z.number().min(1).max(10000),
	allowedExtensions: z.array(z.string()),
	blockedExtensions: z.array(z.string()),
})

/**
 * Gets default path security config for security level
 */
export function getDefaultPathConfig(securityLevel: SecurityLevel): PathSecurityConfig {
	return { ...DEFAULT_PATH_CONFIGS[securityLevel] }
}

/**
 * Creates a secure path validator with custom configuration
 */
export function createPathValidator(
	config?: Partial<PathSecurityConfig>,
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
) {
	const pathConfig = {
		...DEFAULT_PATH_CONFIGS[securityLevel],
		...config,
	}

	return (inputPath: string): PathValidationResult => {
		return validatePath(inputPath, pathConfig, securityLevel)
	}
}
