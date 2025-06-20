import React from "react"
import { Badge } from "@src/components/ui/badge"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@src/components/ui/tooltip"

export type SecurityStatus = "verified" | "unverified" | "failed" | "pinned"

export interface SchemaSecurityBadgeProps {
	status: SecurityStatus
	domain?: string
	fingerprint?: string
	error?: string
	className?: string
	showTooltip?: boolean
}

const getStatusConfig = (status: SecurityStatus) => {
	switch (status) {
		case "verified":
			return {
				variant: "default" as const,
				icon: "codicon-shield",
				text: "Verified",
				className: "bg-vscode-charts-green text-vscode-button-foreground",
				tooltipTitle: "Schema Verified",
				tooltipDescription: "This tool's schema has been cryptographically verified and is trusted.",
			}
		case "pinned":
			return {
				variant: "default" as const,
				icon: "codicon-lock",
				text: "Pinned",
				className: "bg-vscode-button-background text-vscode-button-foreground",
				tooltipTitle: "Key Pinned",
				tooltipDescription: "This tool's public key has been pinned for enhanced security.",
			}
		case "unverified":
			return {
				variant: "outline" as const,
				icon: "codicon-warning",
				text: "Unverified",
				className: "bg-vscode-charts-yellow text-vscode-editor-foreground border-vscode-charts-yellow",
				tooltipTitle: "Schema Unverified",
				tooltipDescription: "This tool's schema could not be verified. Use with caution.",
			}
		case "failed":
			return {
				variant: "destructive" as const,
				icon: "codicon-error",
				text: "Failed",
				className: "bg-vscode-errorForeground text-vscode-button-foreground",
				tooltipTitle: "Verification Failed",
				tooltipDescription: "Schema verification failed. This tool may be compromised.",
			}
	}
}

export const SchemaSecurityBadge: React.FC<SchemaSecurityBadgeProps> = ({
	status,
	domain,
	fingerprint,
	error,
	className = "",
	showTooltip = true,
}) => {
	const config = getStatusConfig(status)

	const badge = (
		<Badge
			variant={config.variant}
			className={`inline-flex items-center gap-1 text-xs font-medium ${config.className} ${className}`}
			role="status"
			aria-label={`Security status: ${config.text}`}>
			<span className={`codicon ${config.icon}`} aria-hidden="true" />
			<span>{config.text}</span>
		</Badge>
	)

	if (!showTooltip) {
		return badge
	}

	const tooltipContent = (
		<div className="space-y-2">
			<div className="font-medium text-vscode-notifications-foreground">{config.tooltipTitle}</div>
			<div className="text-xs text-vscode-descriptionForeground">{config.tooltipDescription}</div>
			{domain && (
				<div className="text-xs">
					<span className="text-vscode-descriptionForeground">Domain: </span>
					<span className="text-vscode-notifications-foreground font-mono">{domain}</span>
				</div>
			)}
			{fingerprint && (
				<div className="text-xs">
					<span className="text-vscode-descriptionForeground">Fingerprint: </span>
					<span className="text-vscode-notifications-foreground font-mono text-xs break-all">
						{fingerprint.slice(0, 16)}...
					</span>
				</div>
			)}
			{error && status === "failed" && (
				<div className="text-xs">
					<span className="text-vscode-errorForeground">Error: </span>
					<span className="text-vscode-notifications-foreground">{error}</span>
				</div>
			)}
		</div>
	)

	return (
		<TooltipProvider>
			<Tooltip>
				<TooltipTrigger asChild>{badge}</TooltipTrigger>
				<TooltipContent side="top" className="max-w-xs">
					{tooltipContent}
				</TooltipContent>
			</Tooltip>
		</TooltipProvider>
	)
}

export default SchemaSecurityBadge
