/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Persistent permission storage and retrieval system.
 * Handles secure storage of permissions with encryption and backup.
 */

import * as fs from "fs/promises"
import * as path from "path"
import { z } from "zod"
import { Permission, PermissionRequest, PermissionSchema, PermissionRequestSchema } from "./permissionManager"

/**
 * Storage configuration
 */
export interface PermissionStoreConfig {
	storageDir: string
	encryptionEnabled: boolean
	backupEnabled: boolean
	maxBackups: number
	compressionEnabled: boolean
	autoCleanup: boolean
	cleanupInterval: number // milliseconds
}

/**
 * Storage metadata
 */
export interface StorageMetadata {
	version: string
	createdAt: number
	lastModified: number
	permissionCount: number
	requestCount: number
	checksum?: string
}

/**
 * Storage file structure
 */
export interface PermissionStorageData {
	metadata: StorageMetadata
	permissions: Permission[]
	requests: PermissionRequest[]
}

/**
 * Zod schemas for storage validation
 */
export const PermissionStoreConfigSchema = z.object({
	storageDir: z.string(),
	encryptionEnabled: z.boolean(),
	backupEnabled: z.boolean(),
	maxBackups: z.number().positive(),
	compressionEnabled: z.boolean(),
	autoCleanup: z.boolean(),
	cleanupInterval: z.number().positive(),
})

export const StorageMetadataSchema = z.object({
	version: z.string(),
	createdAt: z.number(),
	lastModified: z.number(),
	permissionCount: z.number(),
	requestCount: z.number(),
	checksum: z.string().optional(),
})

export const PermissionStorageDataSchema = z.object({
	metadata: StorageMetadataSchema,
	permissions: z.array(PermissionSchema),
	requests: z.array(PermissionRequestSchema),
})

/**
 * Default storage configuration
 */
export const DEFAULT_PERMISSION_STORE_CONFIG: PermissionStoreConfig = {
	storageDir: ".roo/permissions",
	encryptionEnabled: false, // Simplified for initial implementation
	backupEnabled: true,
	maxBackups: 10,
	compressionEnabled: false, // Simplified for initial implementation
	autoCleanup: true,
	cleanupInterval: 24 * 60 * 60 * 1000, // 24 hours
}

/**
 * Permission storage manager
 */
export class PermissionStore {
	private config: PermissionStoreConfig
	private storageFile: string
	private backupDir: string
	private cleanupTimer?: NodeJS.Timeout

	constructor(config: PermissionStoreConfig = DEFAULT_PERMISSION_STORE_CONFIG) {
		this.config = config
		this.storageFile = path.join(config.storageDir, "permissions.json")
		this.backupDir = path.join(config.storageDir, "backups")

		if (config.autoCleanup) {
			this.startAutoCleanup()
		}
	}

	/**
	 * Initialize storage directory and files
	 */
	async initialize(): Promise<void> {
		try {
			// Create storage directory
			await fs.mkdir(this.config.storageDir, { recursive: true })

			if (this.config.backupEnabled) {
				await fs.mkdir(this.backupDir, { recursive: true })
			}

			// Create initial storage file if it doesn't exist
			try {
				await fs.access(this.storageFile)
			} catch {
				await this.createInitialStorage()
			}

			// Validate existing storage
			await this.validateStorage()
		} catch (error) {
			throw new Error(
				`Failed to initialize permission storage: ${error instanceof Error ? error.message : error}`,
			)
		}
	}

	/**
	 * Create initial storage file
	 */
	private async createInitialStorage(): Promise<void> {
		const initialData: PermissionStorageData = {
			metadata: {
				version: "1.0.0",
				createdAt: Date.now(),
				lastModified: Date.now(),
				permissionCount: 0,
				requestCount: 0,
			},
			permissions: [],
			requests: [],
		}

		await this.writeStorageData(initialData)
	}

	/**
	 * Validate storage file integrity
	 */
	private async validateStorage(): Promise<void> {
		try {
			const data = await this.readStorageData()
			PermissionStorageDataSchema.parse(data)
		} catch (error) {
			throw new Error(`Storage validation failed: ${error instanceof Error ? error.message : error}`)
		}
	}

	/**
	 * Read storage data from file
	 */
	private async readStorageData(): Promise<PermissionStorageData> {
		try {
			const content = await fs.readFile(this.storageFile, "utf-8")
			return JSON.parse(content)
		} catch (error) {
			throw new Error(`Failed to read storage data: ${error instanceof Error ? error.message : error}`)
		}
	}

	/**
	 * Write storage data to file
	 */
	private async writeStorageData(data: PermissionStorageData): Promise<void> {
		try {
			// Create backup if enabled
			if (this.config.backupEnabled) {
				await this.createBackup()
			}

			// Update metadata
			data.metadata.lastModified = Date.now()
			data.metadata.permissionCount = data.permissions.length
			data.metadata.requestCount = data.requests.length

			// Write to file
			const content = JSON.stringify(data, null, 2)
			await fs.writeFile(this.storageFile, content, "utf-8")
		} catch (error) {
			throw new Error(`Failed to write storage data: ${error instanceof Error ? error.message : error}`)
		}
	}

	/**
	 * Create backup of current storage
	 */
	private async createBackup(): Promise<void> {
		if (!this.config.backupEnabled) return

		try {
			// Check if storage file exists
			try {
				await fs.access(this.storageFile)
			} catch {
				return // No file to backup
			}

			const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
			const backupFile = path.join(this.backupDir, `permissions-${timestamp}.json`)

			await fs.copyFile(this.storageFile, backupFile)

			// Clean up old backups
			await this.cleanupOldBackups()
		} catch (error) {
			console.error(`Failed to create backup: ${error instanceof Error ? error.message : error}`)
		}
	}

	/**
	 * Clean up old backup files
	 */
	private async cleanupOldBackups(): Promise<void> {
		try {
			const files = await fs.readdir(this.backupDir)
			const backupFiles = files
				.filter((file) => file.startsWith("permissions-") && file.endsWith(".json"))
				.map((file) => ({
					name: file,
					path: path.join(this.backupDir, file),
				}))

			if (backupFiles.length <= this.config.maxBackups) return

			// Sort by name (which includes timestamp) and remove oldest
			backupFiles.sort((a, b) => a.name.localeCompare(b.name))
			const filesToDelete = backupFiles.slice(0, backupFiles.length - this.config.maxBackups)

			for (const file of filesToDelete) {
				await fs.unlink(file.path)
			}
		} catch (error) {
			console.error(`Failed to cleanup old backups: ${error instanceof Error ? error.message : error}`)
		}
	}

	/**
	 * Save permissions to storage
	 */
	async savePermissions(permissions: Permission[]): Promise<void> {
		const data = await this.readStorageData()
		data.permissions = permissions
		await this.writeStorageData(data)
	}

	/**
	 * Load permissions from storage
	 */
	async loadPermissions(): Promise<Permission[]> {
		const data = await this.readStorageData()
		return data.permissions
	}

	/**
	 * Save a single permission
	 */
	async savePermission(permission: Permission): Promise<void> {
		const data = await this.readStorageData()
		const existingIndex = data.permissions.findIndex((p) => p.id === permission.id)

		if (existingIndex >= 0) {
			data.permissions[existingIndex] = permission
		} else {
			data.permissions.push(permission)
		}

		await this.writeStorageData(data)
	}

	/**
	 * Delete a permission
	 */
	async deletePermission(permissionId: string): Promise<boolean> {
		const data = await this.readStorageData()
		const initialLength = data.permissions.length
		data.permissions = data.permissions.filter((p) => p.id !== permissionId)

		if (data.permissions.length < initialLength) {
			await this.writeStorageData(data)
			return true
		}

		return false
	}

	/**
	 * Save permission requests to storage
	 */
	async saveRequests(requests: PermissionRequest[]): Promise<void> {
		const data = await this.readStorageData()
		data.requests = requests
		await this.writeStorageData(data)
	}

	/**
	 * Load permission requests from storage
	 */
	async loadRequests(): Promise<PermissionRequest[]> {
		const data = await this.readStorageData()
		return data.requests
	}

	/**
	 * Save a single permission request
	 */
	async saveRequest(request: PermissionRequest): Promise<void> {
		const data = await this.readStorageData()
		const existingIndex = data.requests.findIndex((r) => r.id === request.id)

		if (existingIndex >= 0) {
			data.requests[existingIndex] = request
		} else {
			data.requests.push(request)
		}

		await this.writeStorageData(data)
	}

	/**
	 * Delete a permission request
	 */
	async deleteRequest(requestId: string): Promise<boolean> {
		const data = await this.readStorageData()
		const initialLength = data.requests.length
		data.requests = data.requests.filter((r) => r.id !== requestId)

		if (data.requests.length < initialLength) {
			await this.writeStorageData(data)
			return true
		}

		return false
	}

	/**
	 * Get storage metadata
	 */
	async getMetadata(): Promise<StorageMetadata> {
		const data = await this.readStorageData()
		return data.metadata
	}

	/**
	 * Clean up expired permissions and requests
	 */
	async cleanup(): Promise<{ permissionsRemoved: number; requestsRemoved: number }> {
		const data = await this.readStorageData()
		const now = Date.now()

		const initialPermissionCount = data.permissions.length
		const initialRequestCount = data.requests.length

		// Remove expired permissions
		data.permissions = data.permissions.filter((permission) => {
			return !permission.expiresAt || permission.expiresAt > now
		})

		// Remove expired requests
		data.requests = data.requests.filter((request) => {
			return !request.expiresAt || request.expiresAt > now
		})

		await this.writeStorageData(data)

		return {
			permissionsRemoved: initialPermissionCount - data.permissions.length,
			requestsRemoved: initialRequestCount - data.requests.length,
		}
	}

	/**
	 * Export permissions to a backup file
	 */
	async exportPermissions(exportPath: string): Promise<void> {
		const data = await this.readStorageData()
		const exportData = {
			...data,
			exportedAt: Date.now(),
			exportVersion: "1.0.0",
		}

		await fs.writeFile(exportPath, JSON.stringify(exportData, null, 2), "utf-8")
	}

	/**
	 * Import permissions from a backup file
	 */
	async importPermissions(importPath: string, merge: boolean = false): Promise<void> {
		try {
			const content = await fs.readFile(importPath, "utf-8")
			const importData = JSON.parse(content)

			// Validate import data
			PermissionStorageDataSchema.parse(importData)

			if (merge) {
				// Merge with existing data
				const existingData = await this.readStorageData()

				// Merge permissions (avoid duplicates by ID)
				const existingPermissionIds = new Set(existingData.permissions.map((p) => p.id))
				const newPermissions = importData.permissions.filter(
					(p: Permission) => !existingPermissionIds.has(p.id),
				)
				existingData.permissions.push(...newPermissions)

				// Merge requests (avoid duplicates by ID)
				const existingRequestIds = new Set(existingData.requests.map((r) => r.id))
				const newRequests = importData.requests.filter((r: PermissionRequest) => !existingRequestIds.has(r.id))
				existingData.requests.push(...newRequests)

				await this.writeStorageData(existingData)
			} else {
				// Replace existing data
				await this.writeStorageData(importData)
			}
		} catch (error) {
			throw new Error(`Failed to import permissions: ${error instanceof Error ? error.message : error}`)
		}
	}

	/**
	 * Get storage statistics
	 */
	async getStatistics(): Promise<{
		totalPermissions: number
		activePermissions: number
		expiredPermissions: number
		totalRequests: number
		pendingRequests: number
		expiredRequests: number
		storageSize: number
		lastModified: number
	}> {
		const data = await this.readStorageData()
		const now = Date.now()

		const activePermissions = data.permissions.filter((p) => !p.expiresAt || p.expiresAt > now).length

		const expiredPermissions = data.permissions.filter((p) => p.expiresAt && p.expiresAt <= now).length

		const pendingRequests = data.requests.filter((r) => !r.expiresAt || r.expiresAt > now).length

		const expiredRequests = data.requests.filter((r) => r.expiresAt && r.expiresAt <= now).length

		// Get file size
		let storageSize = 0
		try {
			const stats = await fs.stat(this.storageFile)
			storageSize = stats.size
		} catch {
			// File might not exist
		}

		return {
			totalPermissions: data.permissions.length,
			activePermissions,
			expiredPermissions,
			totalRequests: data.requests.length,
			pendingRequests,
			expiredRequests,
			storageSize,
			lastModified: data.metadata.lastModified,
		}
	}

	/**
	 * Start automatic cleanup timer
	 */
	private startAutoCleanup(): void {
		this.cleanupTimer = setInterval(async () => {
			try {
				await this.cleanup()
			} catch (error) {
				console.error(`Auto cleanup failed: ${error instanceof Error ? error.message : error}`)
			}
		}, this.config.cleanupInterval)
	}

	/**
	 * Stop automatic cleanup timer
	 */
	stopAutoCleanup(): void {
		if (this.cleanupTimer) {
			clearInterval(this.cleanupTimer)
			this.cleanupTimer = undefined
		}
	}

	/**
	 * Dispose of the store
	 */
	dispose(): void {
		this.stopAutoCleanup()
	}
}
