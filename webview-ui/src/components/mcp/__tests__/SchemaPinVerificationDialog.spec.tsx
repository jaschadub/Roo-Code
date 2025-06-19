import { render, screen, fireEvent } from "@testing-library/react"
import { SchemaPinVerificationDialog } from "../SchemaPinVerificationDialog"
import { VerificationResult, PinnedKeyInfo } from "@src/types/schemapin"

const mockVerificationResult: VerificationResult = {
	valid: true,
	pinned: false,
	firstUse: true,
	keyFingerprint: "abc123def456",
	developerInfo: {
		developerName: "Test Developer",
		contact: "test@example.com",
		schemaVersion: "1.0.0",
		publicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
		revokedKeys: [],
	},
}

const mockKeyInfo: PinnedKeyInfo = {
	toolId: "test-tool",
	publicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	domain: "example.com",
	developerName: "Test Developer",
	pinnedAt: new Date("2023-01-01"),
	lastVerified: new Date("2023-01-02"),
	fingerprint: "abc123def456",
}

describe("SchemaPinVerificationDialog", () => {
	const defaultProps = {
		isOpen: true,
		onClose: vi.fn(),
		verificationResult: mockVerificationResult,
		toolName: "test-tool",
		serverName: "test-server",
		domain: "example.com",
	}

	beforeEach(() => {
		vi.clearAllMocks()
	})

	it("renders dialog with basic information", () => {
		render(<SchemaPinVerificationDialog {...defaultProps} />)

		expect(screen.getByText("Schema Verification Details")).toBeInTheDocument()
		expect(screen.getByText("Security information for test-tool from test-server")).toBeInTheDocument()
		expect(screen.getByText("test-tool")).toBeInTheDocument()
		expect(screen.getByText("test-server")).toBeInTheDocument()
		expect(screen.getByText("example.com")).toBeInTheDocument()
	})

	it("shows verified status for valid verification", () => {
		render(<SchemaPinVerificationDialog {...defaultProps} />)

		expect(screen.getByText("Unverified")).toBeInTheDocument()
	})

	it("shows failed status for invalid verification", () => {
		const failedResult: VerificationResult = {
			valid: false,
			pinned: false,
			firstUse: false,
			error: "Invalid signature",
		}

		render(<SchemaPinVerificationDialog {...defaultProps} verificationResult={failedResult} />)

		expect(screen.getByText("Failed")).toBeInTheDocument()
		expect(screen.getByText("Invalid signature")).toBeInTheDocument()
	})

	it("shows pinned status when key is pinned", () => {
		const pinnedResult: VerificationResult = {
			valid: true,
			pinned: true,
			firstUse: false,
			keyFingerprint: "abc123def456",
		}

		render(
			<SchemaPinVerificationDialog {...defaultProps} verificationResult={pinnedResult} keyInfo={mockKeyInfo} />,
		)

		expect(screen.getByText("Pinned")).toBeInTheDocument()
	})

	it("displays developer information when available", () => {
		render(<SchemaPinVerificationDialog {...defaultProps} />)

		expect(screen.getByText("Developer Information")).toBeInTheDocument()
		expect(screen.getByText("Test Developer")).toBeInTheDocument()
		expect(screen.getByText("test@example.com")).toBeInTheDocument()
		expect(screen.getByText("1.0.0")).toBeInTheDocument()
	})

	it("displays key information", () => {
		render(<SchemaPinVerificationDialog {...defaultProps} />)

		expect(screen.getByText("Key Information")).toBeInTheDocument()
		expect(screen.getByText("abc123def456")).toBeInTheDocument()
	})

	it("shows pin key button for valid unverified tools", () => {
		const onPinKey = vi.fn()
		render(<SchemaPinVerificationDialog {...defaultProps} onPinKey={onPinKey} />)

		const pinButton = screen.getByText("Pin Key")
		expect(pinButton).toBeInTheDocument()

		fireEvent.click(pinButton)
		expect(onPinKey).toHaveBeenCalledOnce()
	})

	it("shows remove pin button for pinned tools", () => {
		const pinnedResult: VerificationResult = {
			valid: true,
			pinned: true,
			firstUse: false,
			keyFingerprint: "abc123def456",
		}

		const onRemovePin = vi.fn()
		render(
			<SchemaPinVerificationDialog
				{...defaultProps}
				verificationResult={pinnedResult}
				keyInfo={mockKeyInfo}
				onRemovePin={onRemovePin}
			/>,
		)

		const removePinButton = screen.getByText("Remove Pin")
		expect(removePinButton).toBeInTheDocument()

		fireEvent.click(removePinButton)
		expect(onRemovePin).toHaveBeenCalledOnce()
	})

	it("shows retry button for failed verifications", () => {
		const failedResult: VerificationResult = {
			valid: false,
			pinned: false,
			firstUse: false,
			error: "Network error",
		}

		const onRetryVerification = vi.fn()
		render(
			<SchemaPinVerificationDialog
				{...defaultProps}
				verificationResult={failedResult}
				onRetryVerification={onRetryVerification}
			/>,
		)

		const retryButton = screen.getByText("Retry")
		expect(retryButton).toBeInTheDocument()

		fireEvent.click(retryButton)
		expect(onRetryVerification).toHaveBeenCalledOnce()
	})

	it("shows first use warning", () => {
		render(<SchemaPinVerificationDialog {...defaultProps} />)

		expect(screen.getByText("First Use")).toBeInTheDocument()
		expect(screen.getByText(/This is the first time you're using this tool/)).toBeInTheDocument()
	})

	it("calls onClose when close button is clicked", () => {
		const onClose = vi.fn()
		render(<SchemaPinVerificationDialog {...defaultProps} onClose={onClose} />)

		const closeButtons = screen.getAllByRole("button", { name: "Close" })
		fireEvent.click(closeButtons[0]) // Click the main close button, not the X button
		expect(onClose).toHaveBeenCalledOnce()
	})

	it("displays pinned key information when available", () => {
		const pinnedResult: VerificationResult = {
			valid: true,
			pinned: true,
			firstUse: false,
			keyFingerprint: "abc123def456",
		}

		render(
			<SchemaPinVerificationDialog {...defaultProps} verificationResult={pinnedResult} keyInfo={mockKeyInfo} />,
		)

		expect(screen.getByText("12/31/2022")).toBeInTheDocument() // pinnedAt
		expect(screen.getByText("1/1/2023")).toBeInTheDocument() // lastVerified
	})
})
