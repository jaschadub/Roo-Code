import { render, screen, fireEvent } from "@testing-library/react"
import { SchemaPinSettings } from "../SchemaPinSettings"

// Mock VSCode components
vi.mock("@vscode/webview-ui-toolkit/react", () => ({
	VSCodeCheckbox: ({ checked, onChange, children, ...props }: any) => (
		<label>
			<input
				type="checkbox"
				checked={checked}
				onChange={onChange}
				role="checkbox"
				aria-checked={checked}
				aria-label={typeof children === "string" ? children : children?.props?.children}
				{...props}
			/>
			{children}
		</label>
	),
	VSCodeTextField: ({ value, onChange, placeholder, ...props }: any) => (
		<input type="text" value={value} onChange={onChange} placeholder={placeholder} {...props} />
	),
	VSCodeButton: ({ children, onClick, disabled, ...props }: any) => (
		<button onClick={onClick} disabled={disabled} {...props}>
			{children}
		</button>
	),
}))

// Mock UI components
vi.mock("@/components/ui", () => ({
	Slider: ({ value, onValueChange, min, max, step, ...props }: any) => (
		<input
			type="range"
			value={value?.[0] || 0}
			onChange={(e) => onValueChange?.([parseInt(e.target.value)])}
			min={min}
			max={max}
			step={step}
			{...props}
		/>
	),
}))

const mockProps = {
	schemaPinEnabled: true,
	schemaPinStrictMode: false,
	schemaPinAutoPin: false,
	schemaPinVerificationTimeout: 5000,
	schemaPinTrustedDomains: ["example.com"],
	schemaPinBlockedDomains: ["malicious.com"],
	setSchemaPinEnabled: vi.fn(),
	setSchemaPinStrictMode: vi.fn(),
	setSchemaPinAutoPin: vi.fn(),
	setSchemaPinVerificationTimeout: vi.fn(),
	setSchemaPinTrustedDomains: vi.fn(),
	setSchemaPinBlockedDomains: vi.fn(),
}

describe("SchemaPinSettings", () => {
	beforeEach(() => {
		vi.clearAllMocks()
	})

	it("renders SchemaPin settings section", () => {
		render(<SchemaPinSettings {...mockProps} />)

		expect(screen.getByText("SchemaPin Security")).toBeInTheDocument()
		expect(screen.getByText("Enable SchemaPin Verification")).toBeInTheDocument()
	})

	it("shows enabled state correctly", () => {
		render(<SchemaPinSettings {...mockProps} />)

		const enableCheckbox = screen.getByRole("checkbox", { name: /Enable SchemaPin Verification/i })
		expect(enableCheckbox).toHaveAttribute("aria-checked", "true")
	})

	it("shows disabled state correctly", () => {
		render(<SchemaPinSettings {...mockProps} schemaPinEnabled={false} />)

		const enableCheckbox = screen.getByRole("checkbox", { name: /Enable SchemaPin Verification/i })
		expect(enableCheckbox).toHaveAttribute("aria-checked", "false")
	})

	it("calls setSchemaPinEnabled when enable checkbox is toggled", () => {
		render(<SchemaPinSettings {...mockProps} />)

		const enableCheckbox = screen.getByRole("checkbox", { name: /Enable SchemaPin Verification/i })
		fireEvent.click(enableCheckbox)

		expect(mockProps.setSchemaPinEnabled).toHaveBeenCalledWith(false)
	})

	it("shows advanced settings when enabled", () => {
		render(<SchemaPinSettings {...mockProps} />)

		expect(screen.getByText("Security Mode")).toBeInTheDocument()
		expect(screen.getByText("Strict Mode")).toBeInTheDocument()
		expect(screen.getByText("Auto-Pin Keys")).toBeInTheDocument()
		expect(screen.getByText("Trusted Domains")).toBeInTheDocument()
		expect(screen.getByText("Blocked Domains")).toBeInTheDocument()
	})

	it("hides advanced settings when disabled", () => {
		render(<SchemaPinSettings {...mockProps} schemaPinEnabled={false} />)

		expect(screen.queryByText("Security Mode")).not.toBeInTheDocument()
		expect(screen.queryByText("Strict Mode")).not.toBeInTheDocument()
		expect(screen.queryByText("Auto-Pin Keys")).not.toBeInTheDocument()
	})

	it("displays trusted domains correctly", () => {
		render(<SchemaPinSettings {...mockProps} />)

		expect(screen.getByText("example.com")).toBeInTheDocument()
	})

	it("displays blocked domains correctly", () => {
		render(<SchemaPinSettings {...mockProps} />)

		expect(screen.getByText("malicious.com")).toBeInTheDocument()
	})

	it("calls setSchemaPinStrictMode when strict mode is toggled", () => {
		render(<SchemaPinSettings {...mockProps} />)

		const strictModeCheckbox = screen.getByRole("checkbox", { name: /Strict Mode/i })
		fireEvent.click(strictModeCheckbox)

		expect(mockProps.setSchemaPinStrictMode).toHaveBeenCalledWith(true)
	})

	it("calls setSchemaPinAutoPin when auto-pin is toggled", () => {
		render(<SchemaPinSettings {...mockProps} />)

		const autoPinCheckbox = screen.getByRole("checkbox", { name: /Auto-Pin Keys/i })
		fireEvent.click(autoPinCheckbox)

		expect(mockProps.setSchemaPinAutoPin).toHaveBeenCalledWith(true)
	})

	it("displays verification timeout correctly", () => {
		render(<SchemaPinSettings {...mockProps} />)

		expect(screen.getByText("Verification Timeout: 5000ms")).toBeInTheDocument()
	})

	it("shows trusted domains section", () => {
		render(<SchemaPinSettings {...mockProps} />)

		expect(screen.getByText("Trusted Domains")).toBeInTheDocument()
		expect(screen.getByText("Domains in this list bypass verification and are always allowed.")).toBeInTheDocument()
	})

	it("shows blocked domains section", () => {
		render(<SchemaPinSettings {...mockProps} />)

		expect(screen.getByText("Blocked Domains")).toBeInTheDocument()
		expect(
			screen.getByText("Domains in this list are never allowed, regardless of verification status."),
		).toBeInTheDocument()
	})

	it("shows security explanation", () => {
		render(<SchemaPinSettings {...mockProps} />)

		expect(screen.getByText("How SchemaPin Works")).toBeInTheDocument()
		expect(screen.getByText(/SchemaPin uses cryptographic signatures/)).toBeInTheDocument()
	})
})
