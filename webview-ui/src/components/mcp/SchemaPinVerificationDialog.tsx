import React from "react"
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@src/components/ui/dialog"
import { Button } from "@src/components/ui/button"
import { Badge } from "@src/components/ui/badge"
import { VerificationResult, PinnedKeyInfo } from "@src/types/schemapin"
import { SchemaSecurityBadge, SecurityStatus } from "./SchemaSecurityBadge"

export interface SchemaPinVerificationDialogProps {
	isOpen: boolean
	onClose: () => void
	verificationResult: VerificationResult
	keyInfo?: PinnedKeyInfo
	toolName: string
	serverName: string
	domain?: string
	onPinKey?: () => void
	onRemovePin?: () => void
	onRetryVerification?: () => void
}

const getSecurityStatus = (result: VerificationResult): SecurityStatus => {
	if (!result.valid) return "failed"
	if (result.pinned) return "pinned"
	if (result.valid && !result.firstUse) return "verified"
	return "unverified"
}

export const SchemaPinVerificationDialog: React.FC<SchemaPinVerificationDialogProps> = ({
	isOpen,
	onClose,
	verificationResult,
	keyInfo,
	toolName,
	serverName,
	domain,
	onPinKey,
	onRemovePin,
	onRetryVerification,
}) => {
	const securityStatus = getSecurityStatus(verificationResult)
	const showPinActions = verificationResult.valid && !verificationResult.pinned
	const showRemovePin = verificationResult.pinned && keyInfo

	return (
		<Dialog open={isOpen} onOpenChange={onClose}>
			<DialogContent className="max-w-md">
				<DialogHeader>
					<DialogTitle className="flex items-center gap-2">
						<span className="codicon codicon-shield" aria-hidden="true" />
						Schema Verification Details
					</DialogTitle>
					<DialogDescription>
						Security information for {toolName} from {serverName}
					</DialogDescription>
				</DialogHeader>

				<div className="space-y-4">
					{/* Status Badge */}
					<div className="flex items-center justify-between">
						<span className="text-sm font-medium text-vscode-foreground">Status:</span>
						<SchemaSecurityBadge
							status={securityStatus}
							domain={domain}
							fingerprint={verificationResult.keyFingerprint || keyInfo?.fingerprint}
							error={verificationResult.error}
							showTooltip={false}
						/>
					</div>

					{/* Tool Information */}
					<div className="space-y-2 p-3 bg-vscode-textCodeBlock-background rounded border border-vscode-input-border">
						<div className="flex justify-between text-sm">
							<span className="text-vscode-descriptionForeground">Tool:</span>
							<span className="text-vscode-foreground font-mono">{toolName}</span>
						</div>
						<div className="flex justify-between text-sm">
							<span className="text-vscode-descriptionForeground">Server:</span>
							<span className="text-vscode-foreground font-mono">{serverName}</span>
						</div>
						{domain && (
							<div className="flex justify-between text-sm">
								<span className="text-vscode-descriptionForeground">Domain:</span>
								<span className="text-vscode-foreground font-mono">{domain}</span>
							</div>
						)}
					</div>

					{/* Developer Information */}
					{verificationResult.developerInfo && (
						<div className="space-y-2 p-3 bg-vscode-textCodeBlock-background rounded border border-vscode-input-border">
							<div className="text-sm font-medium text-vscode-foreground mb-2">Developer Information</div>
							<div className="flex justify-between text-sm">
								<span className="text-vscode-descriptionForeground">Name:</span>
								<span className="text-vscode-foreground">
									{verificationResult.developerInfo.developerName}
								</span>
							</div>
							{verificationResult.developerInfo.contact && (
								<div className="flex justify-between text-sm">
									<span className="text-vscode-descriptionForeground">Contact:</span>
									<span className="text-vscode-foreground">
										{verificationResult.developerInfo.contact}
									</span>
								</div>
							)}
							<div className="flex justify-between text-sm">
								<span className="text-vscode-descriptionForeground">Schema Version:</span>
								<span className="text-vscode-foreground font-mono">
									{verificationResult.developerInfo.schemaVersion}
								</span>
							</div>
						</div>
					)}

					{/* Key Information */}
					{(verificationResult.keyFingerprint || keyInfo) && (
						<div className="space-y-2 p-3 bg-vscode-textCodeBlock-background rounded border border-vscode-input-border">
							<div className="text-sm font-medium text-vscode-foreground mb-2">Key Information</div>
							<div className="flex justify-between text-sm">
								<span className="text-vscode-descriptionForeground">Fingerprint:</span>
								<span className="text-vscode-foreground font-mono text-xs break-all">
									{verificationResult.keyFingerprint || keyInfo?.fingerprint}
								</span>
							</div>
							{keyInfo?.pinnedAt && (
								<div className="flex justify-between text-sm">
									<span className="text-vscode-descriptionForeground">Pinned:</span>
									<span className="text-vscode-foreground">
										{keyInfo.pinnedAt.toLocaleDateString()}
									</span>
								</div>
							)}
							{keyInfo?.lastVerified && (
								<div className="flex justify-between text-sm">
									<span className="text-vscode-descriptionForeground">Last Verified:</span>
									<span className="text-vscode-foreground">
										{keyInfo.lastVerified.toLocaleDateString()}
									</span>
								</div>
							)}
						</div>
					)}

					{/* Error Information */}
					{verificationResult.error && (
						<div className="p-3 bg-vscode-inputValidation-errorBackground border border-vscode-errorForeground rounded">
							<div className="flex items-center gap-2 mb-2">
								<span
									className="codicon codicon-error text-vscode-errorForeground"
									aria-hidden="true"
								/>
								<span className="text-sm font-medium text-vscode-errorForeground">
									Verification Error
								</span>
							</div>
							<div className="text-sm text-vscode-foreground break-words">{verificationResult.error}</div>
						</div>
					)}

					{/* First Use Warning */}
					{verificationResult.firstUse && verificationResult.valid && (
						<div className="p-3 bg-vscode-inputValidation-warningBackground border border-vscode-charts-yellow rounded">
							<div className="flex items-center gap-2 mb-2">
								<span
									className="codicon codicon-warning text-vscode-charts-yellow"
									aria-hidden="true"
								/>
								<span className="text-sm font-medium text-vscode-foreground">First Use</span>
							</div>
							<div className="text-sm text-vscode-foreground">
								This is the first time you're using this tool. Consider pinning the key for enhanced
								security.
							</div>
						</div>
					)}
				</div>

				<DialogFooter className="flex gap-2">
					{/* Retry button for failed verifications */}
					{!verificationResult.valid && onRetryVerification && (
						<Button variant="secondary" onClick={onRetryVerification}>
							<span className="codicon codicon-refresh mr-2" aria-hidden="true" />
							Retry
						</Button>
					)}

					{/* Pin key button */}
					{showPinActions && onPinKey && (
						<Button variant="default" onClick={onPinKey}>
							<span className="codicon codicon-lock mr-2" aria-hidden="true" />
							Pin Key
						</Button>
					)}

					{/* Remove pin button */}
					{showRemovePin && onRemovePin && (
						<Button variant="destructive" onClick={onRemovePin}>
							<span className="codicon codicon-unlock mr-2" aria-hidden="true" />
							Remove Pin
						</Button>
					)}

					{/* Close button */}
					<Button variant="secondary" onClick={onClose}>
						Close
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	)
}

export default SchemaPinVerificationDialog
