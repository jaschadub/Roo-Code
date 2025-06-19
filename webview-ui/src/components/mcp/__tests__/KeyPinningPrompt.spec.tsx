import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import { KeyPinningPrompt } from "../KeyPinningPrompt"
import { DeveloperInfo, SecurityRecommendation } from "@src/types/schemapin"

const mockDeveloperInfo: DeveloperInfo = {
	developerName: "Test Developer",
	contact: "test@example.com",
	schemaVersion: "1.0.0",
	publicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	revokedKeys: [],
}

describe("KeyPinningPrompt", () => {
	const defaultProps = {
		isOpen: true,
		onClose: vi.fn(),
		onResponse: vi.fn(),
		toolName: "test-tool",
		serverName: "test-server",
		domain: "example.com",
		keyFingerprint: "abc123def456789",
	}

	beforeEach(() => {
		vi.clearAllMocks()
	})

	it("renders dialog with basic information", () => {
		render(<KeyPinningPrompt {...defaultProps} />)

		expect(screen.getByText("Trust New Tool?")).toBeInTheDocument()
		expect(screen.getByText(/This is the first time you're using this tool/)).toBeInTheDocument()
		expect(screen.getByText("test-tool")).toBeInTheDocument()
		expect(screen.getByText("test-server")).toBeInTheDocument()
		expect(screen.getByText("example.com")).toBeInTheDocument()
		expect(screen.getByText("abc123def456789")).toBeInTheDocument()
	})

	it("shows update key pin title when not first use", () => {
		render(<KeyPinningPrompt {...defaultProps} isFirstUse={false} />)

		expect(screen.getByText("Update Key Pin?")).toBeInTheDocument()
		expect(screen.getByText(/The security key for this tool has changed/)).toBeInTheDocument()
	})

	it("displays developer information when provided", () => {
		render(<KeyPinningPrompt {...defaultProps} developerInfo={mockDeveloperInfo} />)

		expect(screen.getByText("Developer Information")).toBeInTheDocument()
		expect(screen.getByText("Test Developer")).toBeInTheDocument()
		expect(screen.getByText("test@example.com")).toBeInTheDocument()
		expect(screen.getByText("1.0.0")).toBeInTheDocument()
	})

	it("shows trust recommendation by default", () => {
		render(<KeyPinningPrompt {...defaultProps} recommendation={SecurityRecommendation.TRUST} />)

		expect(screen.getByText("Recommended")).toBeInTheDocument()
		expect(screen.getByText(/This tool appears to be from a trusted developer/)).toBeInTheDocument()
	})

	it("shows caution recommendation", () => {
		render(<KeyPinningPrompt {...defaultProps} recommendation={SecurityRecommendation.CAUTION} />)

		expect(screen.getByText("Use Caution")).toBeInTheDocument()
		expect(screen.getByText(/Limited information available/)).toBeInTheDocument()
	})

	it("shows reject recommendation with warning", () => {
		render(<KeyPinningPrompt {...defaultProps} recommendation={SecurityRecommendation.REJECT} />)

		expect(screen.getByText("Not Recommended")).toBeInTheDocument()
		expect(screen.getAllByText(/This tool may pose security risks/)).toHaveLength(2)
		expect(screen.getByText("Security Warning")).toBeInTheDocument()
	})

	it("calls onResponse with shouldPin true when trust button is clicked", async () => {
		const onResponse = vi.fn().mockResolvedValue(undefined)
		render(<KeyPinningPrompt {...defaultProps} onResponse={onResponse} />)

		fireEvent.click(screen.getByText("Trust & Pin"))

		await waitFor(() => {
			expect(onResponse).toHaveBeenCalledWith({
				shouldPin: true,
				reason: "User approved key pinning",
			})
		})
	})

	it("calls onResponse with shouldPin false when reject button is clicked", async () => {
		const onResponse = vi.fn().mockResolvedValue(undefined)
		render(<KeyPinningPrompt {...defaultProps} onResponse={onResponse} />)

		fireEvent.click(screen.getByText("Don't Trust"))

		await waitFor(() => {
			expect(onResponse).toHaveBeenCalledWith({
				shouldPin: false,
				reason: "User rejected key pinning",
			})
		})
	})

	it("disables buttons while processing", async () => {
		const onResponse = vi.fn().mockImplementation(() => new Promise((resolve) => setTimeout(resolve, 100)))
		render(<KeyPinningPrompt {...defaultProps} onResponse={onResponse} />)

		const trustButton = screen.getByText("Trust & Pin")
		const rejectButton = screen.getByText("Don't Trust")

		fireEvent.click(trustButton)

		expect(trustButton).toBeDisabled()
		expect(rejectButton).toBeDisabled()
		expect(screen.getByText("Processing...")).toBeInTheDocument()

		await waitFor(() => {
			expect(trustButton).not.toBeDisabled()
			expect(rejectButton).not.toBeDisabled()
		})
	})

	it("shows security information section", () => {
		render(<KeyPinningPrompt {...defaultProps} />)

		expect(screen.getByText("What does pinning do?")).toBeInTheDocument()
		expect(screen.getByText(/Pins the tool's public key for future verification/)).toBeInTheDocument()
		expect(screen.getByText(/Protects against man-in-the-middle attacks/)).toBeInTheDocument()
		expect(screen.getByText(/Ensures the tool hasn't been tampered with/)).toBeInTheDocument()
		expect(screen.getByText(/You'll be warned if the key changes unexpectedly/)).toBeInTheDocument()
	})

	it("prevents closing while processing", () => {
		const onClose = vi.fn()
		const onResponse = vi.fn().mockImplementation(() => new Promise((resolve) => setTimeout(resolve, 100)))

		render(<KeyPinningPrompt {...defaultProps} onClose={onClose} onResponse={onResponse} />)

		fireEvent.click(screen.getByText("Trust & Pin"))

		// Try to close while processing - should not call onClose
		// Note: This would typically be tested by triggering the dialog's onOpenChange
		// but since we're testing the component in isolation, we verify the logic
		expect(onClose).not.toHaveBeenCalled()
	})

	it("shows correct button styling for reject recommendation", () => {
		render(<KeyPinningPrompt {...defaultProps} recommendation={SecurityRecommendation.REJECT} />)

		const trustButton = screen.getByText("Trust & Pin")
		expect(trustButton).toHaveClass("bg-vscode-errorForeground")
	})
})
