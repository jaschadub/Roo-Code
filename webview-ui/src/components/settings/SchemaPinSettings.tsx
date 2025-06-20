import { VSCodeButton, VSCodeCheckbox, VSCodeTextField } from "@vscode/webview-ui-toolkit/react"
import { Shield, Plus, X, Info, AlertTriangle } from "lucide-react"
import { HTMLAttributes, useState, useCallback } from "react"

import { Slider } from "@/components/ui"
import { useAppTranslation } from "@/i18n/TranslationContext"
import { cn } from "@/lib/utils"

import { Section } from "./Section"
import { SectionHeader } from "./SectionHeader"
import { SetCachedStateField } from "./types"

type SchemaPinSettingsProps = HTMLAttributes<HTMLDivElement> & {
	schemaPinEnabled?: boolean
	schemaPinStrictMode?: boolean
	schemaPinAutoPin?: boolean
	schemaPinVerificationTimeout?: number
	schemaPinTrustedDomains?: string[]
	schemaPinBlockedDomains?: string[]
	setSchemaPinEnabled: (value: boolean) => void
	setSchemaPinStrictMode: (value: boolean) => void
	setSchemaPinAutoPin: (value: boolean) => void
	setSchemaPinVerificationTimeout: (value: number) => void
	setSchemaPinTrustedDomains: (value: string[]) => void
	setSchemaPinBlockedDomains: (value: string[]) => void
}

export const SchemaPinSettings = ({
	schemaPinEnabled,
	schemaPinStrictMode,
	schemaPinAutoPin,
	schemaPinVerificationTimeout,
	schemaPinTrustedDomains,
	schemaPinBlockedDomains,
	setSchemaPinEnabled,
	setSchemaPinStrictMode,
	setSchemaPinAutoPin,
	setSchemaPinVerificationTimeout,
	setSchemaPinTrustedDomains,
	setSchemaPinBlockedDomains,
	className,
	...props
}: SchemaPinSettingsProps) => {
	const { t } = useAppTranslation()

	const [newTrustedDomain, setNewTrustedDomain] = useState("")
	const [newBlockedDomain, setNewBlockedDomain] = useState("")

	const addTrustedDomain = useCallback(() => {
		if (newTrustedDomain.trim() && !schemaPinTrustedDomains?.includes(newTrustedDomain.trim())) {
			setSchemaPinTrustedDomains([...(schemaPinTrustedDomains || []), newTrustedDomain.trim()])
			setNewTrustedDomain("")
		}
	}, [newTrustedDomain, schemaPinTrustedDomains, setSchemaPinTrustedDomains])

	const removeTrustedDomain = useCallback(
		(domain: string) => {
			setSchemaPinTrustedDomains(schemaPinTrustedDomains?.filter((d) => d !== domain) || [])
		},
		[schemaPinTrustedDomains, setSchemaPinTrustedDomains],
	)

	const addBlockedDomain = useCallback(() => {
		if (newBlockedDomain.trim() && !schemaPinBlockedDomains?.includes(newBlockedDomain.trim())) {
			setSchemaPinBlockedDomains([...(schemaPinBlockedDomains || []), newBlockedDomain.trim()])
			setNewBlockedDomain("")
		}
	}, [newBlockedDomain, schemaPinBlockedDomains, setSchemaPinBlockedDomains])

	const removeBlockedDomain = useCallback(
		(domain: string) => {
			setSchemaPinBlockedDomains(schemaPinBlockedDomains?.filter((d) => d !== domain) || [])
		},
		[schemaPinBlockedDomains, setSchemaPinBlockedDomains],
	)

	return (
		<div className={cn("flex flex-col gap-2", className)} {...props}>
			<SectionHeader>
				<div className="flex items-center gap-2">
					<Shield className="w-4" />
					<div>SchemaPin Security</div>
				</div>
			</SectionHeader>

			<Section>
				{/* Enable SchemaPin */}
				<div>
					<VSCodeCheckbox
						checked={schemaPinEnabled ?? false}
						onChange={(e: any) => setSchemaPinEnabled(e.target.checked)}>
						<span className="font-medium">Enable SchemaPin Verification</span>
					</VSCodeCheckbox>
					<div className="text-vscode-descriptionForeground text-sm mt-1">
						<div className="flex items-start gap-2">
							<Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
							<div>
								SchemaPin provides cryptographic verification of MCP tool schemas to ensure they haven't
								been tampered with. This helps protect against malicious modifications to tool
								definitions.
							</div>
						</div>
					</div>
				</div>

				{schemaPinEnabled && (
					<div className="flex flex-col gap-4 pl-3 border-l-2 border-vscode-button-background">
						{/* Security Mode Settings */}
						<div className="flex flex-col gap-3">
							<h4 className="font-medium text-vscode-foreground">Security Mode</h4>

							<div>
								<VSCodeCheckbox
									checked={schemaPinStrictMode}
									onChange={(e: any) => setSchemaPinStrictMode(e.target.checked)}>
									<span className="font-medium">Strict Mode</span>
								</VSCodeCheckbox>
								<div className="text-vscode-descriptionForeground text-sm mt-1">
									<div className="flex items-start gap-2">
										<AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0 text-yellow-500" />
										<div>
											In strict mode, tools without valid signatures will be rejected. Disable
											this to allow unsigned tools with a warning.
										</div>
									</div>
								</div>
							</div>

							<div>
								<VSCodeCheckbox
									checked={schemaPinAutoPin}
									onChange={(e: any) => setSchemaPinAutoPin(e.target.checked)}>
									<span className="font-medium">Auto-Pin Keys</span>
								</VSCodeCheckbox>
								<div className="text-vscode-descriptionForeground text-sm mt-1">
									Automatically pin public keys for new tools without prompting. When disabled, you'll
									be asked to confirm each new key.
								</div>
							</div>
						</div>

						{/* Verification Timeout */}
						<div>
							<label className="block font-medium mb-2">
								Verification Timeout: {schemaPinVerificationTimeout || 5000}ms
							</label>
							<div className="flex items-center gap-2">
								<Slider
									min={1000}
									max={30000}
									step={1000}
									value={[schemaPinVerificationTimeout || 5000]}
									onValueChange={([value]) => setSchemaPinVerificationTimeout(value)}
									className="flex-1"
								/>
							</div>
							<div className="text-vscode-descriptionForeground text-sm mt-1">
								Maximum time to wait for schema verification operations to complete.
							</div>
						</div>

						{/* Trusted Domains */}
						<div>
							<h4 className="font-medium text-vscode-foreground mb-2">Trusted Domains</h4>
							<div className="text-vscode-descriptionForeground text-sm mb-3">
								Domains in this list bypass verification and are always allowed.
							</div>

							<div className="flex gap-2 mb-2">
								<VSCodeTextField
									value={newTrustedDomain}
									onChange={(e: any) => setNewTrustedDomain(e.target.value)}
									placeholder="example.com"
									onKeyDown={(e: any) => {
										if (e.key === "Enter") {
											e.preventDefault()
											addTrustedDomain()
										}
									}}
									style={{ flexGrow: 1 }}
								/>
								<VSCodeButton onClick={addTrustedDomain} disabled={!newTrustedDomain.trim()}>
									<Plus className="w-4 h-4" />
								</VSCodeButton>
							</div>

							{schemaPinTrustedDomains && schemaPinTrustedDomains.length > 0 && (
								<div className="flex flex-wrap gap-2">
									{schemaPinTrustedDomains.map((domain) => (
										<div
											key={domain}
											className="flex items-center gap-1 px-2 py-1 bg-vscode-button-background rounded text-sm">
											<span>{domain}</span>
											<button
												onClick={() => removeTrustedDomain(domain)}
												className="text-vscode-descriptionForeground hover:text-vscode-foreground">
												<X className="w-3 h-3" />
											</button>
										</div>
									))}
								</div>
							)}
						</div>

						{/* Blocked Domains */}
						<div>
							<h4 className="font-medium text-vscode-foreground mb-2">Blocked Domains</h4>
							<div className="text-vscode-descriptionForeground text-sm mb-3">
								Domains in this list are never allowed, regardless of verification status.
							</div>

							<div className="flex gap-2 mb-2">
								<VSCodeTextField
									value={newBlockedDomain}
									onChange={(e: any) => setNewBlockedDomain(e.target.value)}
									placeholder="malicious.com"
									onKeyDown={(e: any) => {
										if (e.key === "Enter") {
											e.preventDefault()
											addBlockedDomain()
										}
									}}
									style={{ flexGrow: 1 }}
								/>
								<VSCodeButton onClick={addBlockedDomain} disabled={!newBlockedDomain.trim()}>
									<Plus className="w-4 h-4" />
								</VSCodeButton>
							</div>

							{schemaPinBlockedDomains && schemaPinBlockedDomains.length > 0 && (
								<div className="flex flex-wrap gap-2">
									{schemaPinBlockedDomains.map((domain) => (
										<div
											key={domain}
											className="flex items-center gap-1 px-2 py-1 bg-red-800/20 text-red-400 rounded text-sm">
											<span>{domain}</span>
											<button
												onClick={() => removeBlockedDomain(domain)}
												className="text-red-300 hover:text-red-100">
												<X className="w-3 h-3" />
											</button>
										</div>
									))}
								</div>
							)}
						</div>

						{/* Security Policy Explanation */}
						<div className="p-3 bg-vscode-textBlockQuote-background border-l-4 border-vscode-textBlockQuote-border">
							<h5 className="font-medium text-vscode-foreground mb-2">How SchemaPin Works</h5>
							<div className="text-vscode-descriptionForeground text-sm space-y-2">
								<p>
									SchemaPin uses cryptographic signatures to verify that MCP tool schemas haven't been
									modified. Each tool developer signs their schema with a private key, and you pin
									their public key.
								</p>
								<p>
									<strong>First use:</strong> When you encounter a new tool, you'll be prompted to pin
									the developer's public key.
								</p>
								<p>
									<strong>Subsequent uses:</strong> The tool's schema signature is verified against
									the pinned key. If verification fails, the tool may have been tampered with.
								</p>
							</div>
						</div>
					</div>
				)}
			</Section>
		</div>
	)
}
