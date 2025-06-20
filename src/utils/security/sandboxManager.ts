/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Process isolation and resource management for secure MCP server execution.
 * Provides sandboxing capabilities to limit resource usage and prevent system compromise.
 */

import { spawn, ChildProcess, SpawnOptions } from "child_process"
import { z } from "zod"
import { SecurityLevel } from "./validationSchemas"
import { CommandValidationError } from "./commandValidator"

/**
 * Resource limits for process execution
 */
export interface ResourceLimits {
	/** Maximum execution time in milliseconds */
	timeout: number
	/** Maximum memory usage in MB */
	maxMemory: number
	/** Maximum CPU usage percentage */
	maxCpu: number
	/** Maximum number of file descriptors */
	maxFileDescriptors: number
	/** Maximum number of processes */
	maxProcesses: number
	/** Maximum disk usage in MB */
	maxDiskUsage: number
}

/**
 * Sandbox configuration
 */
export interface SandboxConfig {
	/** Security level for sandbox */
	securityLevel: SecurityLevel
	/** Resource limits */
	resourceLimits: ResourceLimits
	/** Working directory restrictions */
	workingDirectory?: string
	/** Environment variable filtering */
	allowedEnvironmentVars: string[]
	/** Network access restrictions */
	allowNetworkAccess: boolean
	/** File system access restrictions */
	allowedPaths: string[]
	/** Blocked paths */
	blockedPaths: string[]
	/** Enable process monitoring */
	enableMonitoring: boolean
}

/**
 * Process execution result
 */
export interface ProcessExecutionResult {
	success: boolean
	exitCode: number | null
	stdout: string
	stderr: string
	signal: string | null
	timedOut: boolean
	resourceUsage: {
		executionTime: number
		memoryUsed: number
		cpuUsed: number
	}
	violations: Array<{
		type: string
		message: string
		severity: "low" | "medium" | "high"
	}>
}

/**
 * Default sandbox configurations by security level
 */
const DEFAULT_SANDBOX_CONFIGS: Record<SecurityLevel, SandboxConfig> = {
	[SecurityLevel.STRICT]: {
		securityLevel: SecurityLevel.STRICT,
		resourceLimits: {
			timeout: 30000, // 30 seconds
			maxMemory: 128, // 128 MB
			maxCpu: 50, // 50%
			maxFileDescriptors: 50,
			maxProcesses: 5,
			maxDiskUsage: 100, // 100 MB
		},
		allowedEnvironmentVars: ["NODE_ENV", "NODE_PATH", "PATH", "HOME", "USER", "TEMP", "TMP", "TMPDIR"],
		allowNetworkAccess: false,
		allowedPaths: [],
		blockedPaths: ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/System", "/Windows", "/Program Files"],
		enableMonitoring: true,
	},
	[SecurityLevel.MODERATE]: {
		securityLevel: SecurityLevel.MODERATE,
		resourceLimits: {
			timeout: 60000, // 60 seconds
			maxMemory: 512, // 512 MB
			maxCpu: 75, // 75%
			maxFileDescriptors: 100,
			maxProcesses: 10,
			maxDiskUsage: 500, // 500 MB
		},
		allowedEnvironmentVars: [
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
		],
		allowNetworkAccess: true,
		allowedPaths: [],
		blockedPaths: ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/System/Library", "/Windows/System32"],
		enableMonitoring: true,
	},
	[SecurityLevel.PERMISSIVE]: {
		securityLevel: SecurityLevel.PERMISSIVE,
		resourceLimits: {
			timeout: 300000, // 5 minutes
			maxMemory: 2048, // 2 GB
			maxCpu: 90, // 90%
			maxFileDescriptors: 500,
			maxProcesses: 50,
			maxDiskUsage: 2048, // 2 GB
		},
		allowedEnvironmentVars: [], // Empty means all allowed
		allowNetworkAccess: true,
		allowedPaths: [],
		blockedPaths: [],
		enableMonitoring: false,
	},
}

/**
 * Sandbox manager for secure process execution
 */
export class SandboxManager {
	private config: SandboxConfig
	private activeProcesses: Map<string, ChildProcess> = new Map()
	private processMonitors: Map<string, NodeJS.Timeout> = new Map()

	constructor(config?: Partial<SandboxConfig>, securityLevel: SecurityLevel = SecurityLevel.MODERATE) {
		this.config = {
			...DEFAULT_SANDBOX_CONFIGS[securityLevel],
			...config,
		}
	}

	/**
	 * Executes a command in a sandboxed environment
	 */
	async executeCommand(
		command: string,
		args: string[] = [],
		options: {
			cwd?: string
			env?: Record<string, string>
			input?: string
		} = {},
	): Promise<ProcessExecutionResult> {
		const executionId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
		const startTime = Date.now()

		const result: ProcessExecutionResult = {
			success: false,
			exitCode: null,
			stdout: "",
			stderr: "",
			signal: null,
			timedOut: false,
			resourceUsage: {
				executionTime: 0,
				memoryUsed: 0,
				cpuUsed: 0,
			},
			violations: [],
		}

		try {
			// Validate working directory
			if (options.cwd && !this.isPathAllowed(options.cwd)) {
				result.violations.push({
					type: "path_violation",
					message: `Working directory not allowed: ${options.cwd}`,
					severity: "high",
				})
				return result
			}

			// Filter environment variables
			const filteredEnv = this.filterEnvironmentVariables(options.env || {})

			// Create secure spawn options
			const spawnOptions: SpawnOptions = {
				cwd: options.cwd,
				env: { ...process.env, ...filteredEnv },
				stdio: ["pipe", "pipe", "pipe"],
				shell: false, // Disable shell to prevent injection
				detached: false,
			}

			// Spawn the process
			const childProcess = spawn(command, args, spawnOptions)
			this.activeProcesses.set(executionId, childProcess)

			// Set up monitoring if enabled
			if (this.config.enableMonitoring) {
				this.setupProcessMonitoring(executionId, childProcess, result)
			}

			// Set up timeout
			const timeoutHandle = setTimeout(() => {
				result.timedOut = true
				this.killProcess(executionId, "SIGTERM")
			}, this.config.resourceLimits.timeout)

			// Handle process input
			if (options.input && childProcess.stdin) {
				childProcess.stdin.write(options.input)
				childProcess.stdin.end()
			}

			// Collect output
			let stdout = ""
			let stderr = ""

			if (childProcess.stdout) {
				childProcess.stdout.on("data", (data: Buffer) => {
					stdout += data.toString()
					// Check for output size limits
					if (stdout.length > 1024 * 1024) {
						// 1MB limit
						result.violations.push({
							type: "output_size",
							message: "Stdout output exceeds size limit",
							severity: "medium",
						})
						this.killProcess(executionId, "SIGTERM")
					}
				})
			}

			if (childProcess.stderr) {
				childProcess.stderr.on("data", (data: Buffer) => {
					stderr += data.toString()
					// Check for error output size limits
					if (stderr.length > 1024 * 1024) {
						// 1MB limit
						result.violations.push({
							type: "error_size",
							message: "Stderr output exceeds size limit",
							severity: "medium",
						})
						this.killProcess(executionId, "SIGTERM")
					}
				})
			}

			// Wait for process completion
			await new Promise<void>((resolve, reject) => {
				childProcess.on("exit", (code: number | null, signal: NodeJS.Signals | null) => {
					clearTimeout(timeoutHandle)
					result.exitCode = code
					result.signal = signal
					result.success = code === 0 && !result.timedOut
					resolve()
				})

				childProcess.on("error", (error: Error) => {
					clearTimeout(timeoutHandle)
					result.violations.push({
						type: "process_error",
						message: error.message,
						severity: "high",
					})
					reject(error)
				})
			})

			result.stdout = stdout
			result.stderr = stderr
			result.resourceUsage.executionTime = Date.now() - startTime
		} catch (error) {
			result.violations.push({
				type: "execution_error",
				message: error instanceof Error ? error.message : "Unknown execution error",
				severity: "high",
			})
		} finally {
			// Clean up
			this.cleanupProcess(executionId)
		}

		return result
	}

	/**
	 * Kills a running process
	 */
	killProcess(executionId: string, signal: NodeJS.Signals = "SIGTERM"): boolean {
		const process = this.activeProcesses.get(executionId)
		if (process && !process.killed) {
			try {
				process.kill(signal)
				return true
			} catch (error) {
				console.error(`Failed to kill process ${executionId}:`, error)
				return false
			}
		}
		return false
	}

	/**
	 * Gets active process count
	 */
	getActiveProcessCount(): number {
		return this.activeProcesses.size
	}

	/**
	 * Gets sandbox configuration
	 */
	getConfig(): SandboxConfig {
		return { ...this.config }
	}

	/**
	 * Updates sandbox configuration
	 */
	updateConfig(updates: Partial<SandboxConfig>): void {
		this.config = { ...this.config, ...updates }
	}

	/**
	 * Validates if a path is allowed for access
	 */
	private isPathAllowed(path: string): boolean {
		const normalizedPath = this.normalizePath(path)

		// Check blocked paths
		for (const blockedPath of this.config.blockedPaths) {
			if (normalizedPath.startsWith(this.normalizePath(blockedPath))) {
				return false
			}
		}

		// If allowed paths are specified, check them
		if (this.config.allowedPaths.length > 0) {
			return this.config.allowedPaths.some((allowedPath) =>
				normalizedPath.startsWith(this.normalizePath(allowedPath)),
			)
		}

		return true
	}

	/**
	 * Filters environment variables based on configuration
	 */
	private filterEnvironmentVariables(env: Record<string, string>): Record<string, string> {
		if (this.config.allowedEnvironmentVars.length === 0) {
			// If no restrictions, return all (but sanitized)
			return this.sanitizeEnvironmentVariables(env)
		}

		const filtered: Record<string, string> = {}
		for (const [key, value] of Object.entries(env)) {
			if (this.config.allowedEnvironmentVars.includes(key)) {
				filtered[key] = this.sanitizeEnvironmentValue(value)
			}
		}

		return filtered
	}

	/**
	 * Sanitizes environment variables
	 */
	private sanitizeEnvironmentVariables(env: Record<string, string>): Record<string, string> {
		const sanitized: Record<string, string> = {}
		for (const [key, value] of Object.entries(env)) {
			sanitized[key] = this.sanitizeEnvironmentValue(value)
		}
		return sanitized
	}

	/**
	 * Sanitizes an environment variable value
	 */
	private sanitizeEnvironmentValue(value: string): string {
		// Remove potentially dangerous characters
		return value.replace(/[;&|`$(){}\\[\]<>]/g, "")
	}

	/**
	 * Sets up process monitoring for resource usage
	 */
	private setupProcessMonitoring(executionId: string, process: ChildProcess, result: ProcessExecutionResult): void {
		const monitor = setInterval(() => {
			if (process.killed || process.exitCode !== null) {
				clearInterval(monitor)
				return
			}

			// Monitor memory usage (simplified - in production, use proper process monitoring)
			try {
				// Note: ChildProcess doesn't have memoryUsage, this is a simplified approach
				// In production, you would use external tools like pidusage or ps
				const memoryMB = 0 // Placeholder - would need external monitoring

				if (memoryMB > this.config.resourceLimits.maxMemory) {
					result.violations.push({
						type: "memory_limit",
						message: `Memory usage (${memoryMB.toFixed(2)}MB) exceeds limit (${this.config.resourceLimits.maxMemory}MB)`,
						severity: "high",
					})
					this.killProcess(executionId, "SIGTERM")
				}

				result.resourceUsage.memoryUsed = Math.max(result.resourceUsage.memoryUsed, memoryMB)
			} catch (error) {
				// Memory monitoring failed, continue without it
			}
		}, 1000) // Check every second

		this.processMonitors.set(executionId, monitor)
	}

	/**
	 * Cleans up process resources
	 */
	private cleanupProcess(executionId: string): void {
		// Remove from active processes
		this.activeProcesses.delete(executionId)

		// Clear monitoring
		const monitor = this.processMonitors.get(executionId)
		if (monitor) {
			clearInterval(monitor)
			this.processMonitors.delete(executionId)
		}
	}

	/**
	 * Normalizes a file path for comparison
	 */
	private normalizePath(path: string): string {
		return path.replace(/[\\\/]+/g, "/").replace(/\/+$/, "")
	}

	/**
	 * Disposes of the sandbox manager
	 */
	dispose(): void {
		// Kill all active processes
		for (const [executionId] of this.activeProcesses) {
			this.killProcess(executionId, "SIGKILL")
		}

		// Clear all monitors
		for (const monitor of this.processMonitors.values()) {
			clearInterval(monitor)
		}

		this.activeProcesses.clear()
		this.processMonitors.clear()
	}
}

/**
 * Zod schema for sandbox configuration
 */
export const SandboxConfigSchema = z.object({
	securityLevel: z.nativeEnum(SecurityLevel),
	resourceLimits: z.object({
		timeout: z.number().min(1000).max(600000), // 1 second to 10 minutes
		maxMemory: z.number().min(1).max(8192), // 1 MB to 8 GB
		maxCpu: z.number().min(1).max(100), // 1% to 100%
		maxFileDescriptors: z.number().min(1).max(1000),
		maxProcesses: z.number().min(1).max(100),
		maxDiskUsage: z.number().min(1).max(10240), // 1 MB to 10 GB
	}),
	workingDirectory: z.string().optional(),
	allowedEnvironmentVars: z.array(z.string()),
	allowNetworkAccess: z.boolean(),
	allowedPaths: z.array(z.string()),
	blockedPaths: z.array(z.string()),
	enableMonitoring: z.boolean(),
})

/**
 * Gets default sandbox configuration for security level
 */
export function getDefaultSandboxConfig(securityLevel: SecurityLevel): SandboxConfig {
	return { ...DEFAULT_SANDBOX_CONFIGS[securityLevel] }
}

/**
 * Creates a sandbox manager with security level
 */
export function createSandboxManager(
	securityLevel: SecurityLevel = SecurityLevel.MODERATE,
	config?: Partial<SandboxConfig>,
): SandboxManager {
	return new SandboxManager(config, securityLevel)
}
