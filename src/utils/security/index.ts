/**
 * Copyright 2025 Jascha Wanger / Tarnover, LLC / ThirdKey.ai
 *
 * Security utilities for MCP tool parameter validation and sanitization.
 *
 * This module provides comprehensive input validation and sanitization
 * to prevent command injection, XSS, and data exfiltration attacks.
 */

// Core sanitization functions
export {
	sanitizeString,
	sanitizeObject,
	sanitizeArray,
	sanitizeValue,
	validateSanitizedValue,
	createSanitizationConfig,
	SecurityValidationError,
	DEFAULT_SANITIZATION_CONFIG,
	type SanitizationConfig,
} from "./inputSanitizer"

// Validation schemas
export {
	SecurityLevel,
	serverNameSchema,
	toolNameSchema,
	uriSchema,
	createToolArgumentsSchema,
	createMcpToolParamsSchema,
	createMcpResourceParamsSchema,
	validateMcpToolParams,
	validateMcpResourceParams,
	type ValidationContext,
	type ValidationResult,
	type McpToolParams,
	type McpResourceParams,
} from "./validationSchemas"

// Security utilities and management
export {
	SecurityManager,
	getSecurityManager,
	processValidationResult,
	createSecurityErrorMessage,
	validateServerName,
	validateToolName,
	sanitizeErrorMessage,
	isSecurityViolation,
	isValidationError,
	DEFAULT_SECURITY_POLICY,
	type SecurityPolicy,
	type SecurityViolationRecord,
	type SecurityMetrics,
} from "./securityUtils"

// Command validation and security
export {
	validateCommand,
	validateWorkingDirectory,
	createSecureCommandWrapper,
	CommandValidationError,
	getDefaultCommandConfig,
	CommandValidationConfigSchema,
	type CommandValidationConfig,
	type CommandValidationResult,
} from "./commandValidator"

// Process sandboxing and isolation
export {
	SandboxManager,
	createSandboxManager,
	getDefaultSandboxConfig,
	SandboxConfigSchema,
	type SandboxConfig,
	type ResourceLimits,
	type ProcessExecutionResult,
} from "./sandboxManager"

// Path security and validation
export {
	validatePath,
	validateWorkingDirectory as validateWorkingDirectoryPath,
	securePathResolve,
	createPathValidator,
	PathSecurityError,
	getDefaultPathConfig,
	PathSecurityConfigSchema,
	type PathSecurityConfig,
	type PathValidationResult,
} from "./pathSecurity"

// Enhanced permission management system
export {
	PermissionManager,
	PermissionScope,
	PermissionType,
	PermissionCondition,
	PermissionStatus,
	DEFAULT_PERMISSION_POLICY,
	PermissionScopeSchema,
	PermissionTypeSchema,
	PermissionStatusSchema,
	PermissionConditionSchema,
	PermissionSchema,
	PermissionRequestSchema,
	PermissionPolicySchema,
	type Permission,
	type PermissionRequest,
	type PermissionValidationResult,
	type PermissionPolicy,
	type ResourceConstraints,
	type UsageQuota,
	type TimeConstraints,
	type ConditionalRules,
	type PermissionAuditEntry,
} from "./permissionManager"

// Role-based access control
export {
	AccessControlManager,
	UserRole,
	DEFAULT_ACCESS_CONTROL_POLICY,
	DEFAULT_ROLE_CAPABILITIES,
	UserRoleSchema,
	RoleCapabilitiesSchema,
	UserContextSchema,
	AccessControlPolicySchema,
	type RoleCapabilities,
	type UserContext,
	type AccessControlPolicy,
	type AccessControlResult,
} from "./accessControl"

// Permission storage and persistence
export {
	PermissionStore,
	DEFAULT_PERMISSION_STORE_CONFIG,
	PermissionStoreConfigSchema,
	StorageMetadataSchema,
	PermissionStorageDataSchema,
	type PermissionStoreConfig,
	type StorageMetadata,
	type PermissionStorageData,
} from "./permissionStore"

// Audit logging and monitoring
export {
	AuditLogger,
	AuditEventType,
	AuditSeverity,
	DEFAULT_AUDIT_CONFIG,
	AuditEventTypeSchema,
	AuditSeveritySchema,
	AuditEventSchema,
	AuditLoggerConfigSchema,
	type AuditEvent,
	type AuditQueryFilter,
	type AuditStatistics,
	type AuditLoggerConfig,
} from "./auditLogger"

// Security monitoring and alerting
export {
	SecurityMonitor,
	SecurityAlertType,
	SecurityAlertSeverity,
	SecurityResponseAction,
	DEFAULT_SECURITY_MONITOR_CONFIG,
	SecurityAlertTypeSchema,
	SecurityAlertSeveritySchema,
	SecurityResponseActionSchema,
	SecurityResponseSchema,
	SecurityAlertSchema,
	SecurityMonitorConfigSchema,
	type SecurityAlert,
	type SecurityResponse,
	type SecurityMonitorConfig,
	type SecurityMonitoringMetrics,
	type PatternDetectionResult,
} from "./securityMonitor"

// Compliance reporting
export {
	ComplianceReporter,
	ComplianceReportType,
	ReportFormat,
	ComplianceStandard,
	ComplianceReportTypeSchema,
	ReportFormatSchema,
	ComplianceStandardSchema,
	ComplianceReportConfigSchema,
	ComplianceFindingSchema,
	type ComplianceReportConfig,
	type ComplianceReportMetadata,
	type SecuritySummary,
	type ComplianceFinding,
	type ComplianceReport,
} from "./complianceReporter"

// Anomaly detection
export {
	AnomalyDetector,
	AnomalyDetectionAlgorithm,
	AnomalyType,
	DEFAULT_ANOMALY_DETECTOR_CONFIG,
	AnomalyDetectionAlgorithmSchema,
	AnomalyTypeSchema,
	AnomalyEvidenceSchema,
	AnomalyDetectionResultSchema,
	BehavioralBaselineSchema,
	AnomalyDetectorConfigSchema,
	type AnomalyDetectionResult,
	type AnomalyEvidence,
	type BehavioralBaseline,
	type AnomalyDetectorConfig,
	type StatisticalMetrics,
	type PatternSignature,
} from "./anomalyDetector"

// Network security and communication
export {
	NetworkSecurityManager,
	NetworkSecurityViolation,
	getNetworkSecurityManager,
	validateNetworkSecurity,
	createSecureHTTPSAgent,
	DEFAULT_NETWORK_SECURITY_POLICY,
	NetworkSecurityPolicySchema,
	CertificatePinConfigSchema,
} from "./networkSecurity"

export type { NetworkSecurityPolicy, NetworkSecurityResult, CertificatePinConfig } from "./networkSecurity"

// Certificate management and validation
export {
	CertificateManager,
	getCertificateManager,
	DEFAULT_CERTIFICATE_STORE_CONFIG,
	CertificateInfoSchema,
	CertificateStoreConfigSchema,
	CertificatePinSchema,
} from "./certificateManager"

export type {
	CertificateInfo,
	CertificateValidationResult,
	CertificateStoreConfig,
	CertificatePin,
} from "./certificateManager"

// Authentication and API key management
export {
	AuthenticationManager,
	AuthenticationMethod,
	getAuthenticationManager,
	AuthenticationMethodSchema,
	APIKeyConfigSchema,
	AuthenticationTokenSchema,
	OAuth2ConfigSchema,
} from "./authenticationManager"

export type {
	APIKeyConfig,
	AuthenticationToken,
	AuthenticationResult,
	OAuth2Config,
	RateLimitConfig,
} from "./authenticationManager"

// Secure connection management
export {
	ConnectionSecurityManager,
	getConnectionSecurityManager,
	DEFAULT_CONNECTION_SECURITY_POLICY,
	ConnectionSecurityPolicySchema,
	SecureRequestOptionsSchema,
} from "./connectionSecurity"

export type {
	ConnectionSecurityPolicy,
	ConnectionMetrics,
	ConnectionSecurityEvent,
	SecureRequestOptions,
} from "./connectionSecurity"
