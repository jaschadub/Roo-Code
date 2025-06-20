import { VSCodeCheckbox } from "@vscode/webview-ui-toolkit/react"

import { McpTool } from "@roo/mcp"

import { useAppTranslation } from "@src/i18n/TranslationContext"
import { vscode } from "@src/utils/vscode"
import { SchemaSecurityBadge, SecurityStatus } from "./SchemaSecurityBadge"
import { VerificationResult } from "@src/types/schemapin"

type McpToolRowProps = {
	tool: McpTool
	serverName?: string
	serverSource?: "global" | "project"
	alwaysAllowMcp?: boolean
	verificationResult?: VerificationResult
	domain?: string
	onShowVerificationDetails?: () => void
}

const McpToolRow = ({
	tool,
	serverName,
	serverSource,
	alwaysAllowMcp,
	verificationResult,
	domain,
	onShowVerificationDetails,
}: McpToolRowProps) => {
	const { t } = useAppTranslation()

	const getSecurityStatus = (): SecurityStatus => {
		if (!verificationResult) return "unverified"
		if (!verificationResult.valid) return "failed"
		if (verificationResult.pinned) return "pinned"
		return "verified"
	}

	const handleAlwaysAllowChange = () => {
		if (!serverName) return
		vscode.postMessage({
			type: "toggleToolAlwaysAllow",
			serverName,
			source: serverSource || "global",
			toolName: tool.name,
			alwaysAllow: !tool.alwaysAllow,
		})
	}

	return (
		<div
			key={tool.name}
			style={{
				padding: "3px 0",
			}}>
			<div
				data-testid="tool-row-container"
				style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}
				onClick={(e) => e.stopPropagation()}>
				<div className="flex items-center gap-2">
					<span className="codicon codicon-symbol-method" />
					<span className="font-medium">{tool.name}</span>
					{verificationResult && (
						<SchemaSecurityBadge
							status={getSecurityStatus()}
							domain={domain}
							fingerprint={verificationResult.keyFingerprint}
							error={verificationResult.error}
							className="ml-2"
						/>
					)}
					{onShowVerificationDetails && verificationResult && (
						<button
							onClick={(e) => {
								e.stopPropagation()
								onShowVerificationDetails()
							}}
							className="ml-1 p-1 rounded hover:bg-vscode-toolbar-hoverBackground transition-colors"
							title="Show verification details"
							aria-label="Show schema verification details">
							<span className="codicon codicon-info text-xs" />
						</button>
					)}
				</div>
				{serverName && alwaysAllowMcp && (
					<VSCodeCheckbox checked={tool.alwaysAllow} onChange={handleAlwaysAllowChange} data-tool={tool.name}>
						{t("mcp:tool.alwaysAllow")}
					</VSCodeCheckbox>
				)}
			</div>
			{tool.description && (
				<div
					style={{
						marginLeft: "0px",
						marginTop: "4px",
						opacity: 0.8,
						fontSize: "12px",
					}}>
					{tool.description}
				</div>
			)}
			{tool.inputSchema &&
				"properties" in tool.inputSchema &&
				Object.keys(tool.inputSchema.properties as Record<string, any>).length > 0 && (
					<div
						style={{
							marginTop: "8px",
							fontSize: "12px",
							border: "1px solid color-mix(in srgb, var(--vscode-descriptionForeground) 30%, transparent)",
							borderRadius: "3px",
							padding: "8px",
						}}>
						<div
							style={{ marginBottom: "4px", opacity: 0.8, fontSize: "11px", textTransform: "uppercase" }}>
							{t("mcp:tool.parameters")}
						</div>
						{Object.entries(tool.inputSchema.properties as Record<string, any>).map(
							([paramName, schema]) => {
								const isRequired =
									tool.inputSchema &&
									"required" in tool.inputSchema &&
									Array.isArray(tool.inputSchema.required) &&
									tool.inputSchema.required.includes(paramName)

								return (
									<div
										key={paramName}
										style={{
											display: "flex",
											alignItems: "baseline",
											marginTop: "4px",
										}}>
										<code
											style={{
												color: "var(--vscode-textPreformat-foreground)",
												marginRight: "8px",
											}}>
											{paramName}
											{isRequired && (
												<span style={{ color: "var(--vscode-errorForeground)" }}>*</span>
											)}
										</code>
										<span
											style={{
												opacity: 0.8,
												overflowWrap: "break-word",
												wordBreak: "break-word",
											}}>
											{schema.description || t("mcp:tool.noDescription")}
										</span>
									</div>
								)
							},
						)}
					</div>
				)}
		</div>
	)
}

export default McpToolRow
