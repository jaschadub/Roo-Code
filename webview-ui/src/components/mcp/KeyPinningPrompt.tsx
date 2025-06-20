import React, { useState } from "react"
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
import { DeveloperInfo, PinningPromptResponse, SecurityRecommendation } from "@src/types/schemapin"

export interface KeyPinningPromptProps {
	isOpen: boolean
	onClose: () => void
	onResponse: (response: PinningPromptResponse) => void
	toolName: string
	serverName: string
	domain: string
	keyFingerprint: string
	developerInfo?: DeveloperInfo
	isFirstUse?: boolean
	recommendation?: SecurityRecommendation
}

const getRecommendationConfig = (recommendation: SecurityRecommendation) => {
	switch (recommendation) {
		case SecurityRecommendation.TRUST:
			return {
				color: "bg-vscode-charts-green text-vscode-button-foreground",
				icon: "codicon-shield",
				text: "Recommended",
				description: "This tool appears to be from a trusted developer.",
			}
		case SecurityRecommendation.CAUTION:
			return {
				color: "bg-vscode-charts-yellow text-vscode-editor-foreground",
				icon: "codicon-warning",
				text: "Use Caution",
				description: "Limited information available about this tool's developer.",
			}
		case SecurityRecommendation.REJECT:
			return {
				color: "bg-vscode-errorForeground text-vscode-button-foreground",
				icon: "codicon-error",
				text: "Not Recommended",
				description: "This tool may pose security risks.",
			}
	}
}

export const KeyPinningPrompt: React.FC<KeyPinningPromptProps> = ({
	isOpen,
	onClose,
	onResponse,
	toolName,
	serverName,
	domain,
	keyFingerprint,
	developerInfo,
	isFirstUse = true,
	recommendation = SecurityRecommendation.CAUTION,
}) => {
	const [isProcessing, setIsProcessing] = useState(false)
	const recommendationConfig = getRecommendationConfig(recommendation)

	const handleTrust = async () => {
		setIsProcessing(true)
		try {
			await onResponse({ shouldPin: true, reason: "User approved key pinning" })
		} finally {
			setIsProcessing(false)
		}
	}

	const handleReject = async () => {
		setIsProcessing(true)
		try {
			await onResponse({ shouldPin: false, reason: "User rejected key pinning" })
		} finally {
			setIsProcessing(false)
		}
	}

	const handleClose = () => {
		if (!isProcessing) {
			onClose()
		}
	}

	return (
		<Dialog open={isOpen} onOpenChange={handleClose}>
			<DialogContent className="max-w-lg">
				<DialogHeader>
					<DialogTitle className="flex items-center gap-2">
						<span className="codicon codicon-key" aria-hidden="true" />
						{isFirstUse ? "Trust New Tool?" : "Update Key Pin?"}
					</DialogTitle>
					<DialogDescription>
						{isFirstUse
							? "This is the first time you're using this tool. Do you want to pin its security key?"
							: "The security key for this tool has changed. Do you want to update the pin?"}
					</DialogDescription>
				</DialogHeader>

				<div className="space-y-4">
					{/* Security Recommendation */}
					<div className="flex items-center justify-between p-3 bg-vscode-textCodeBlock-background rounded border border-vscode-input-border">
						<span className="text-sm font-medium text-vscode-foreground">Security Assessment:</span>
						<Badge className={`inline-flex items-center gap-1 ${recommendationConfig.color}`}>
							<span className={`codicon ${recommendationConfig.icon}`} aria-hidden="true" />
							{recommendationConfig.text}
						</Badge>
					</div>

					{/* Tool Information */}
					<div className="space-y-2 p-3 bg-vscode-textCodeBlock-background rounded border border-vscode-input-border">
						<div className="text-sm font-medium text-vscode-foreground mb-2">Tool Information</div>
						<div className="flex justify-between text-sm">
							<span className="text-vscode-descriptionForeground">Tool:</span>
							<span className="text-vscode-foreground font-mono">{toolName}</span>
						</div>
						<div className="flex justify-between text-sm">
							<span className="text-vscode-descriptionForeground">Server:</span>
							<span className="text-vscode-foreground font-mono">{serverName}</span>
						</div>
						<div className="flex justify-between text-sm">
							<span className="text-vscode-descriptionForeground">Domain:</span>
							<span className="text-vscode-foreground font-mono">{domain}</span>
						</div>
					</div>

					{/* Developer Information */}
					{developerInfo && (
						<div className="space-y-2 p-3 bg-vscode-textCodeBlock-background rounded border border-vscode-input-border">
							<div className="text-sm font-medium text-vscode-foreground mb-2">Developer Information</div>
							<div className="flex justify-between text-sm">
								<span className="text-vscode-descriptionForeground">Name:</span>
								<span className="text-vscode-foreground">{developerInfo.developerName}</span>
							</div>
							{developerInfo.contact && (
								<div className="flex justify-between text-sm">
									<span className="text-vscode-descriptionForeground">Contact:</span>
									<span className="text-vscode-foreground">{developerInfo.contact}</span>
								</div>
							)}
							<div className="flex justify-between text-sm">
								<span className="text-vscode-descriptionForeground">Schema Version:</span>
								<span className="text-vscode-foreground font-mono">{developerInfo.schemaVersion}</span>
							</div>
						</div>
					)}

					{/* Key Fingerprint */}
					<div className="space-y-2 p-3 bg-vscode-textCodeBlock-background rounded border border-vscode-input-border">
						<div className="text-sm font-medium text-vscode-foreground mb-2">Security Key</div>
						<div className="flex justify-between text-sm">
							<span className="text-vscode-descriptionForeground">Fingerprint:</span>
							<span className="text-vscode-foreground font-mono text-xs break-all">{keyFingerprint}</span>
						</div>
					</div>

					{/* Security Information */}
					<div className="p-3 bg-vscode-inputValidation-infoBackground border border-vscode-inputValidation-infoBorder rounded">
						<div className="flex items-center gap-2 mb-2">
							<span
								className="codicon codicon-info text-vscode-inputValidation-infoForeground"
								aria-hidden="true"
							/>
							<span className="text-sm font-medium text-vscode-foreground">What does pinning do?</span>
						</div>
						<div className="text-sm text-vscode-foreground space-y-1">
							<p>• Pins the tool's public key for future verification</p>
							<p>• Protects against man-in-the-middle attacks</p>
							<p>• Ensures the tool hasn't been tampered with</p>
							<p>• You'll be warned if the key changes unexpectedly</p>
						</div>
					</div>

					{/* Recommendation Details */}
					<div className="text-sm text-vscode-descriptionForeground">{recommendationConfig.description}</div>

					{/* Warning for untrusted tools */}
					{recommendation === SecurityRecommendation.REJECT && (
						<div className="p-3 bg-vscode-inputValidation-errorBackground border border-vscode-errorForeground rounded">
							<div className="flex items-center gap-2 mb-2">
								<span
									className="codicon codicon-warning text-vscode-errorForeground"
									aria-hidden="true"
								/>
								<span className="text-sm font-medium text-vscode-errorForeground">
									Security Warning
								</span>
							</div>
							<div className="text-sm text-vscode-foreground">
								This tool may pose security risks. Only proceed if you trust the source.
							</div>
						</div>
					)}
				</div>

				<DialogFooter className="flex gap-2">
					<Button variant="secondary" onClick={handleReject} disabled={isProcessing}>
						<span className="codicon codicon-close mr-2" aria-hidden="true" />
						Don't Trust
					</Button>
					<Button
						variant="default"
						onClick={handleTrust}
						disabled={isProcessing}
						className={recommendation === SecurityRecommendation.REJECT ? "bg-vscode-errorForeground" : ""}>
						<span className="codicon codicon-shield mr-2" aria-hidden="true" />
						{isProcessing ? "Processing..." : "Trust & Pin"}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	)
}

export default KeyPinningPrompt
