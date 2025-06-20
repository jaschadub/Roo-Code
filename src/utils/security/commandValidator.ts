/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Command validation and whitelisting utilities for secure MCP server command execution.
 * Provides protection against arbitrary code execution and command injection attacks.
 */

import { z } from "zod"
import { SecurityLevel } from "./validationSchemas"

/**
 * Command validation configuration
 */
export interface CommandValidationConfig {
	/** Security level for command validation */
	securityLevel: SecurityLevel
	/** Allowed executable commands */
	allowedCommands: string[]
	/** Allowed command patterns (regex) */
	allowedPatterns: string[]
	/** Blocked command patterns (regex) */
	blockedPatterns: string[]
	/** Allowed file extensions for executables */
	allowedExecutableExtensions: string[]
	/** Maximum command length */
	maxCommandLength: number
	/** Maximum number of arguments */
	maxArguments: number
	/** Whether to allow relative paths */
	allowRelativePaths: boolean
	/** Whether to allow absolute paths */
	allowAbsolutePaths: boolean
	/** Allowed working directories */
	allowedWorkingDirectories: string[]
}

/**
 * Default command validation configurations by security level
 */
const DEFAULT_COMMAND_CONFIGS: Record<SecurityLevel, CommandValidationConfig> = {
	[SecurityLevel.STRICT]: {
		securityLevel: SecurityLevel.STRICT,
		allowedCommands: ["node", "npm", "npx", "python", "python3", "pip", "pip3"],
		allowedPatterns: [
			"^node\\s+[a-zA-Z0-9._/-]+\\.js$",
			"^npm\\s+(install|run|start|test|build)\\s*",
			"^npx\\s+[a-zA-Z0-9@._/-]+\\s*",
			"^python3?\\s+[a-zA-Z0-9._/-]+\\.py$",
		],
		blockedPatterns: [
			"[;&|`$(){}\\[\\]<>]", // Shell metacharacters
			"\\.\\.[\\/\\\\]", // Path traversal
			"(rm|del|format|fdisk|mkfs)\\s", // Destructive commands
			"(sudo|su|chmod|chown)\\s", // Privilege escalation
			"(curl|wget|nc|netcat)\\s", // Network commands
			"(eval|exec|system)\\s*\\(", // Code execution functions
		],
		allowedExecutableExtensions: [".js", ".py", ".mjs"],
		maxCommandLength: 500,
		maxArguments: 20,
		allowRelativePaths: true,
		allowAbsolutePaths: false,
		allowedWorkingDirectories: [],
	},
	[SecurityLevel.MODERATE]: {
		securityLevel: SecurityLevel.MODERATE,
		allowedCommands: [
			"node",
			"npm",
			"npx",
			"yarn",
			"pnpm",
			"python",
			"python3",
			"pip",
			"pip3",
			"git",
			"docker",
			"kubectl",
			"go",
			"cargo",
			"rustc",
		],
		allowedPatterns: [
			"^(node|npm|npx|yarn|pnpm)\\s+",
			"^python3?\\s+",
			"^git\\s+(clone|pull|push|status|add|commit)\\s*",
			"^docker\\s+(build|run|ps|images)\\s*",
			"^go\\s+(run|build|test)\\s*",
			"^cargo\\s+(run|build|test)\\s*",
		],
		blockedPatterns: [
			"[;&|`$(){}\\[\\]<>]", // Shell metacharacters
			"\\.\\.[\\/\\\\]", // Path traversal
			"(rm|del|format|fdisk|mkfs)\\s+-[rf]", // Destructive commands with flags
			"(sudo|su)\\s", // Privilege escalation
			"(eval|exec|system)\\s*\\(", // Code execution functions
		],
		allowedExecutableExtensions: [".js", ".py", ".mjs", ".ts", ".go", ".rs"],
		maxCommandLength: 1000,
		maxArguments: 50,
		allowRelativePaths: true,
		allowAbsolutePaths: true,
		allowedWorkingDirectories: [],
	},
	[SecurityLevel.PERMISSIVE]: {
		securityLevel: SecurityLevel.PERMISSIVE,
		allowedCommands: [], // Empty means all commands allowed
		allowedPatterns: [".*"], // Allow all patterns
		blockedPatterns: [
			"\\.\\.[\\/\\\\]", // Still block path traversal
			"(eval|exec|system)\\s*\\(", // Still block direct code execution
		],
		allowedExecutableExtensions: [],
		maxCommandLength: 2000,
		maxArguments: 100,
		allowRelativePaths: true,
		allowAbsolutePaths: true,
		allowedWorkingDirectories: [],
	},
}

/**
 * Command validation result
 */
export interface CommandValidationResult {
	isValid: boolean
	sanitizedCommand: string
	sanitizedArgs: string[]
	violations: Array<{
		type: string
		message: string
		severity: "low" | "medium" | "high"
	}>
	securityLevel: SecurityLevel
}

/**
 * Command validation error
 */
export class CommandValidationError extends Error {
	constructor(
		message: string,
		public readonly violations: CommandValidationResult["violations"],
		public readonly command: string,
	) {
		super(message)
		this.name = "CommandValidationError"
	}
}

/**
 * Validates and sanitizes a command for secure execution
 */
export function validateCommand(
	command: string,
	args: string[] = [],
	config?: Partial<CommandValidationConfig>,
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
): CommandValidationResult {
	const validationConfig = {
		...DEFAULT_COMMAND_CONFIGS[securityLevel],
		...config,
	}

	const result: CommandValidationResult = {
		isValid: true,
		sanitizedCommand: command.trim(),
		sanitizedArgs: args.map((arg) => arg.trim()),
		violations: [],
		securityLevel,
	}

	// Validate command length
	const fullCommand = `${command} ${args.join(" ")}`.trim()
	if (fullCommand.length > validationConfig.maxCommandLength) {
		result.violations.push({
			type: "command_length",
			message: `Command exceeds maximum length of ${validationConfig.maxCommandLength}`,
			severity: "medium",
		})
	}

	// Validate argument count
	if (args.length > validationConfig.maxArguments) {
		result.violations.push({
			type: "argument_count",
			message: `Too many arguments (${args.length} > ${validationConfig.maxArguments})`,
			severity: "medium",
		})
	}

	// Check blocked patterns
	for (const pattern of validationConfig.blockedPatterns) {
		const regex = new RegExp(pattern, "gi")
		if (regex.test(fullCommand)) {
			result.violations.push({
				type: "blocked_pattern",
				message: `Command contains blocked pattern: ${pattern}`,
				severity: "high",
			})
		}
	}

	// Check allowed commands (if specified)
	if (validationConfig.allowedCommands.length > 0) {
		const baseCommand = extractBaseCommand(command)
		if (!validationConfig.allowedCommands.includes(baseCommand)) {
			result.violations.push({
				type: "command_not_allowed",
				message: `Command '${baseCommand}' is not in the allowed list`,
				severity: "high",
			})
		}
	}

	// Check allowed patterns (if command is not in allowed list)
	if (validationConfig.allowedPatterns.length > 0) {
		const matchesPattern = validationConfig.allowedPatterns.some((pattern) => {
			const regex = new RegExp(pattern, "gi")
			return regex.test(fullCommand)
		})

		if (!matchesPattern) {
			result.violations.push({
				type: "pattern_not_allowed",
				message: "Command does not match any allowed patterns",
				severity: "high",
			})
		}
	}

	// Validate paths in arguments
	for (const arg of args) {
		const pathValidation = validatePath(arg, validationConfig)
		if (!pathValidation.isValid) {
			result.violations.push(...pathValidation.violations)
		}
	}

	// Validate executable extensions
	if (validationConfig.allowedExecutableExtensions.length > 0) {
		for (const arg of args) {
			if (isExecutableFile(arg)) {
				const extension = getFileExtension(arg)
				if (extension && !validationConfig.allowedExecutableExtensions.includes(extension)) {
					result.violations.push({
						type: "executable_extension",
						message: `Executable file extension '${extension}' is not allowed`,
						severity: "medium",
					})
				}
			}
		}
	}

	// Set overall validity
	result.isValid = result.violations.length === 0 || !result.violations.some((v) => v.severity === "high")

	return result
}

/**
 * Validates a working directory path
 */
export function validateWorkingDirectory(
	cwd: string,
	allowedDirectories: string[] = [],
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
): CommandValidationResult {
	const result: CommandValidationResult = {
		isValid: true,
		sanitizedCommand: "",
		sanitizedArgs: [],
		violations: [],
		securityLevel,
	}

	// Normalize path
	const normalizedPath = normalizePath(cwd)

	// Check for path traversal
	if (normalizedPath.includes("..")) {
		result.violations.push({
			type: "path_traversal",
			message: "Working directory contains path traversal sequences",
			severity: "high",
		})
	}

	// Check allowed directories (if specified)
	if (allowedDirectories.length > 0) {
		const isAllowed = allowedDirectories.some((allowedDir) => {
			const normalizedAllowed = normalizePath(allowedDir)
			return normalizedPath.startsWith(normalizedAllowed)
		})

		if (!isAllowed) {
			result.violations.push({
				type: "directory_not_allowed",
				message: `Working directory '${cwd}' is not in the allowed list`,
				severity: "high",
			})
		}
	}

	result.isValid = result.violations.length === 0 || !result.violations.some((v) => v.severity === "high")

	return result
}

/**
 * Creates a secure command wrapper for Windows/Unix systems
 */
export function createSecureCommandWrapper(
	command: string,
	args: string[],
	options: {
		cwd?: string
		env?: Record<string, string>
		timeout?: number
		securityLevel?: SecurityLevel
	} = {},
): { command: string; args: string[]; options: any } {
	const { cwd, env, timeout = 60000, securityLevel = SecurityLevel.MODERATE } = options

	// Validate the command
	const validation = validateCommand(command, args, undefined, securityLevel)
	if (!validation.isValid) {
		throw new CommandValidationError(
			"Command validation failed",
			validation.violations,
			`${command} ${args.join(" ")}`,
		)
	}

	// Validate working directory if provided
	if (cwd) {
		const cwdValidation = validateWorkingDirectory(cwd, [], securityLevel)
		if (!cwdValidation.isValid) {
			throw new CommandValidationError("Working directory validation failed", cwdValidation.violations, cwd)
		}
	}

	// Filter environment variables
	const filteredEnv = filterEnvironmentVariables(env || {}, securityLevel)

	// Create secure execution options
	const secureOptions = {
		cwd: cwd ? normalizePath(cwd) : undefined,
		env: filteredEnv,
		timeout,
		stdio: ["pipe", "pipe", "pipe"] as const,
		shell: false, // Disable shell to prevent command injection
	}

	return {
		command: validation.sanitizedCommand,
		args: validation.sanitizedArgs,
		options: secureOptions,
	}
}

/**
 * Helper functions
 */

function extractBaseCommand(command: string): string {
	// Extract the base command without path
	const parts = command.trim().split(/\s+/)
	const baseCommand = parts[0]

	// Remove path and extension
	const commandName = baseCommand.split(/[/\\]/).pop() || baseCommand
	return commandName.replace(/\.(exe|cmd|bat|ps1)$/i, "")
}

function validatePath(
	path: string,
	config: CommandValidationConfig,
): { isValid: boolean; violations: CommandValidationResult["violations"] } {
	const violations: CommandValidationResult["violations"] = []

	// Check for path traversal
	if (path.includes("..")) {
		violations.push({
			type: "path_traversal",
			message: `Path contains traversal sequences: ${path}`,
			severity: "high",
		})
	}

	// Check absolute path restrictions
	if (isAbsolutePath(path) && !config.allowAbsolutePaths) {
		violations.push({
			type: "absolute_path",
			message: `Absolute paths are not allowed: ${path}`,
			severity: "medium",
		})
	}

	// Check relative path restrictions
	if (!isAbsolutePath(path) && !config.allowRelativePaths) {
		violations.push({
			type: "relative_path",
			message: `Relative paths are not allowed: ${path}`,
			severity: "medium",
		})
	}

	return {
		isValid: violations.length === 0 || !violations.some((v) => v.severity === "high"),
		violations,
	}
}

function isExecutableFile(path: string): boolean {
	const executableExtensions = [".exe", ".cmd", ".bat", ".ps1", ".sh", ".py", ".js", ".mjs", ".ts"]
	const extension = getFileExtension(path)
	return extension ? executableExtensions.includes(extension.toLowerCase()) : false
}

function getFileExtension(path: string): string | null {
	const match = path.match(/\.[^.]+$/)
	return match ? match[0] : null
}

function isAbsolutePath(path: string): boolean {
	// Windows: C:\ or \\server\share
	// Unix: /path
	return /^([a-zA-Z]:[\\\/]|\\\\|\/)/i.test(path)
}

function normalizePath(path: string): string {
	// Normalize path separators and resolve relative components
	return path
		.replace(/[\\\/]+/g, "/")
		.replace(/\/\.\//g, "/")
		.replace(/\/+/g, "/")
}

function filterEnvironmentVariables(env: Record<string, string>, securityLevel: SecurityLevel): Record<string, string> {
	const filtered: Record<string, string> = {}

	// Define allowed environment variables by security level
	const allowedVars: Record<SecurityLevel, string[]> = {
		[SecurityLevel.STRICT]: [
			"NODE_ENV",
			"NODE_PATH",
			"NODE_OPTIONS",
			"PATH",
			"HOME",
			"USER",
			"USERNAME",
			"TEMP",
			"TMP",
			"TMPDIR",
		],
		[SecurityLevel.MODERATE]: [
			"NODE_ENV",
			"NODE_PATH",
			"NODE_OPTIONS",
			"PATH",
			"HOME",
			"USER",
			"USERNAME",
			"TEMP",
			"TMP",
			"TMPDIR",
			"PYTHONPATH",
			"PYTHON_PATH",
			"GOPATH",
			"GOROOT",
			"CARGO_HOME",
			"RUSTUP_HOME",
		],
		[SecurityLevel.PERMISSIVE]: Object.keys(env), // Allow all in permissive mode
	}

	const allowed = allowedVars[securityLevel]

	for (const [key, value] of Object.entries(env)) {
		if (allowed.includes(key) || allowed.includes("*")) {
			// Sanitize environment variable values
			const sanitizedValue = value.replace(/[;&|`$(){}\\[\]<>]/g, "")
			if (sanitizedValue.length > 0) {
				filtered[key] = sanitizedValue
			}
		}
	}

	return filtered
}

/**
 * Zod schema for command validation configuration
 */
export const CommandValidationConfigSchema = z.object({
	securityLevel: z.nativeEnum(SecurityLevel),
	allowedCommands: z.array(z.string()),
	allowedPatterns: z.array(z.string()),
	blockedPatterns: z.array(z.string()),
	allowedExecutableExtensions: z.array(z.string()),
	maxCommandLength: z.number().min(1).max(10000),
	maxArguments: z.number().min(1).max(1000),
	allowRelativePaths: z.boolean(),
	allowAbsolutePaths: z.boolean(),
	allowedWorkingDirectories: z.array(z.string()),
})

/**
 * Gets default command validation config for security level
 */
export function getDefaultCommandConfig(securityLevel: SecurityLevel): CommandValidationConfig {
	return { ...DEFAULT_COMMAND_CONFIGS[securityLevel] }
}
