import { render, screen } from "@testing-library/react"
import { SchemaSecurityBadge, SecurityStatus } from "../SchemaSecurityBadge"

describe("SchemaSecurityBadge", () => {
	it("renders verified status correctly", () => {
		render(<SchemaSecurityBadge status="verified" domain="example.com" fingerprint="abc123def456" />)

		expect(screen.getByRole("status")).toHaveAttribute("aria-label", "Security status: Verified")
		expect(screen.getByText("Verified")).toBeInTheDocument()
		expect(screen.getByText("Verified").closest("div")).toHaveClass("bg-vscode-charts-green")
	})

	it("renders unverified status correctly", () => {
		render(<SchemaSecurityBadge status="unverified" domain="example.com" />)

		expect(screen.getByRole("status")).toHaveAttribute("aria-label", "Security status: Unverified")
		expect(screen.getByText("Unverified")).toBeInTheDocument()
		expect(screen.getByText("Unverified").closest("div")).toHaveClass("bg-vscode-charts-yellow")
	})

	it("renders failed status correctly", () => {
		render(<SchemaSecurityBadge status="failed" error="Invalid signature" />)

		expect(screen.getByRole("status")).toHaveAttribute("aria-label", "Security status: Failed")
		expect(screen.getByText("Failed")).toBeInTheDocument()
		expect(screen.getByText("Failed").closest("div")).toHaveClass("bg-vscode-errorForeground")
	})

	it("renders pinned status correctly", () => {
		render(<SchemaSecurityBadge status="pinned" domain="example.com" fingerprint="abc123def456" />)

		expect(screen.getByRole("status")).toHaveAttribute("aria-label", "Security status: Pinned")
		expect(screen.getByText("Pinned")).toBeInTheDocument()
		expect(screen.getByText("Pinned").closest("div")).toHaveClass("bg-vscode-button-background")
	})

	it("renders without tooltip when showTooltip is false", () => {
		render(<SchemaSecurityBadge status="verified" showTooltip={false} />)

		expect(screen.getByText("Verified")).toBeInTheDocument()
		// Should not have tooltip trigger wrapper
		expect(screen.queryByRole("button")).not.toBeInTheDocument()
	})

	it("applies custom className", () => {
		render(<SchemaSecurityBadge status="verified" className="custom-class" showTooltip={false} />)

		expect(screen.getByText("Verified").closest("div")).toHaveClass("custom-class")
	})

	it("shows correct icons for each status", () => {
		const { rerender } = render(<SchemaSecurityBadge status="verified" showTooltip={false} />)
		expect(document.querySelector(".codicon-shield")).toBeInTheDocument()

		rerender(<SchemaSecurityBadge status="pinned" showTooltip={false} />)
		expect(document.querySelector(".codicon-lock")).toBeInTheDocument()

		rerender(<SchemaSecurityBadge status="unverified" showTooltip={false} />)
		expect(document.querySelector(".codicon-warning")).toBeInTheDocument()

		rerender(<SchemaSecurityBadge status="failed" showTooltip={false} />)
		expect(document.querySelector(".codicon-error")).toBeInTheDocument()
	})
})
