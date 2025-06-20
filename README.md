<div align="center">
  <h1>Rook Code</h1>
  <p><strong>Security conscious coding agents for VSCode. Zero Trust for AI.</strong></p>
</div>

**Rook Code** is a security-focused **autonomous coding agent** forked from Roo Code that lives in your editor. Built with a "Zero Trust for AI" philosophy, it provides enterprise-grade security while maintaining powerful AI capabilities. Rook Code can:

- Communicate in natural language with comprehensive input sanitization
- Read and write files with enhanced access controls and path validation
- Run terminal commands through secure sandboxing and isolation
- Automate browser actions with security monitoring
- Integrate with any OpenAI-compatible or custom API/model using secure protocols
- Adapt its "personality" and capabilities through **Custom Modes** with security boundaries

Whether you're seeking a flexible coding partner, a system architect, or specialized roles like a QA engineer or product manager, Rook Code helps you build software more efficiently while maintaining the highest security standards.

Check out the [CHANGELOG](CHANGELOG.md) for detailed updates and fixes.

---

## 🔒 Security-First Architecture

Rook Code has undergone a comprehensive security transformation, evolving from **HIGH RISK** to **LOW-MODERATE RISK** through implementation of enterprise-grade security controls across 5 major phases:

### 🛡️ Security Features

- **🔍 Input Sanitization & Validation Framework** - Multi-layered protection against injection attacks
- **🏗️ Command Execution Sandboxing** - Isolated execution environments with strict controls
- **⏰ Time-Limited Access Control** - Enhanced permissions with automatic expiration
- **🌐 Network Security Enforcement** - TLS-only connections with certificate validation
- **📊 Comprehensive Audit Logging** - Real-time monitoring and violation tracking
- **🚨 Anomaly Detection & Alerting** - Proactive threat identification and response

### 🔐 Vulnerabilities Fixed

Rook Code addresses critical security vulnerabilities that were present in the original codebase:

#### **Command Injection Prevention**

- Blocks shell metacharacters and command substitution
- Validates command parameters through secure schemas
- Implements command execution sandboxing

#### **Arbitrary Code Execution Prevention**

- Input sanitization prevents malicious code injection
- Secure parameter validation for all MCP tools
- Controlled execution environments with resource limits

#### **Enhanced Access Control**

- Replaced weak access controls with time-limited permissions
- Implemented role-based access with security levels
- Added server-specific security policies

#### **Network Security Enforcement**

- TLS-only communication with certificate pinning
- Secure authentication mechanisms
- Protected against man-in-the-middle attacks

#### **Information Disclosure Prevention**

- Comprehensive logging controls
- Data sanitization in error messages
- Secure handling of sensitive information

---

## What Can Rook Code Do?

- 🚀 **Generate Code** from natural language descriptions with security validation
- 🔧 **Refactor & Debug** existing code using secure analysis tools
- 📝 **Write & Update** documentation with content sanitization
- 🤔 **Answer Questions** about your codebase through secure knowledge retrieval
- 🔄 **Automate** repetitive tasks within security boundaries
- 🏗️ **Create** new files and projects with access control validation

## Quick Start

Rook Code is in heavy development and testing. If wish to use see Local Setup instructions below.

## Key Features

### Multiple Modes

Rook Code adapts to your needs with specialized modes, each operating within defined security boundaries:

- **Code Mode:** For general-purpose coding tasks with input validation
- **Architect Mode:** For planning and technical leadership with secure documentation
- **Ask Mode:** For answering questions with sanitized responses
- **Debug Mode:** For systematic problem diagnosis with secure logging
- **Custom Modes:** Create unlimited specialized personas with configurable security levels

### Smart Tools with Security

Rook Code comes with powerful tools enhanced with comprehensive security controls:

- **Secure File Operations** - Read and write files with path validation and access controls
- **Sandboxed Command Execution** - Run commands in isolated environments with monitoring
- **Protected Browser Control** - Automate web interactions with security boundaries
- **Secure MCP Integration** - Use external tools via MCP (Model Context Protocol) with comprehensive validation

MCP extends Rook Code's capabilities while maintaining security through:

- **Input Sanitization** - All MCP parameters are validated and sanitized
- **Security Levels** - Configurable security policies per server (STRICT/MODERATE/PERMISSIVE)
- **Violation Tracking** - Real-time monitoring of security violations
- **Access Control** - Time-limited permissions with automatic revocation
- **SchemaPin Integration** - TOFU (Trust-On-First-Use) key pinning for schema verification

### Security-Enhanced Customization

Make Rook Code work your way with security-conscious features:

- **Secure Custom Instructions** - Personalized behavior within security boundaries
- **Protected Custom Modes** - Specialized tasks with configurable security levels
- **Validated Local Models** - Offline use with security monitoring
- **Controlled Auto-Approval** - Faster workflows with security oversight

## 🔒 Security Framework Details

### Input Sanitization & Validation

- **Comprehensive Input Sanitization** - Multi-layer protection against injection attacks
- **Schema Validation** - Zod-based parameter validation for all MCP tools
- **Security Level Configuration** - STRICT/MODERATE/PERMISSIVE security policies
- **Violation Tracking** - Real-time monitoring and logging of security violations

### Command Execution Security

- **Command Validation** - Secure parameter validation and sanitization
- **Sandbox Management** - Isolated execution environments with resource limits
- **Path Security** - Comprehensive path validation and traversal prevention
- **Execution Monitoring** - Real-time command execution tracking

### Access Control Enhancement

- **Permission Management** - Time-limited access with automatic expiration
- **Role-Based Access Control** - Granular permissions based on security levels
- **Server-Specific Policies** - Configurable security rules per MCP server
- **Access Audit Logging** - Comprehensive tracking of all access attempts

### Network Security

- **TLS Enforcement** - Secure communication protocols only
- **Certificate Validation** - Enhanced certificate pinning and validation
- **Authentication Security** - Secure credential management and storage
- **Network Monitoring** - Real-time network activity tracking

### Monitoring & Alerting

- **Security Metrics** - Comprehensive violation and threat tracking
- **Real-time Alerting** - Immediate notification of security events
- **Anomaly Detection** - Proactive identification of suspicious patterns
- **Audit Trail** - Complete security event logging and reporting

### SchemaPin Integration

Rook Code includes comprehensive **SchemaPin** integration for enhanced MCP security:

#### **TOFU Key Pinning**

- **Trust-On-First-Use** - Automatically pin cryptographic keys on first encounter
- **Interactive Pinning** - User confirmation required for new key acceptance
- **Domain Policies** - Configurable trust policies per domain (ALLOW/DENY/PROMPT)
- **Key Management** - Secure storage and rotation of pinned keys

#### **Schema Verification**

- **Cryptographic Validation** - Verify MCP tool schemas using digital signatures
- **Integrity Protection** - Detect tampering or unauthorized schema modifications
- **Automatic Verification** - Real-time schema validation during tool execution
- **Fallback Handling** - Graceful degradation when verification fails

#### **Security Features**

- **Certificate Pinning** - Pin server certificates for enhanced transport security
- **Signature Validation** - Cryptographic verification of tool schemas
- **Revocation Support** - Handle revoked keys and certificates
- **Audit Logging** - Complete audit trail of all verification attempts

[SchemaPin](https://schemapin.org) provides an additional layer of security by ensuring that MCP tools haven't been tampered with and that communications are authentic and authorized.

### Security Levels

#### STRICT

- Maximum security restrictions for untrusted servers
- Blocks file paths, URLs, and shell commands
- Minimal object depth and property limits
- Recommended for external or unknown MCP servers

#### MODERATE (Default)

- Balanced security and functionality
- Allows file paths and URLs but blocks shell commands
- Reasonable limits for most use cases
- Recommended for general-purpose usage

#### PERMISSIVE

- Minimal restrictions for trusted environments
- Allows most content types with monitoring
- Higher limits for complex data processing
- Use only for fully trusted internal servers

## Resources

## Local Setup & Development

1. **Clone** the repo:

```sh
git clone https://github.com/jaschadub/Roo-Code.git
```

2. **Install dependencies**:

```sh
pnpm install
```

3. **Run the extension**:

Press `F5` (or **Run** → **Start Debugging**) in VSCode to open a new window with Rook Code running.

Changes to the webview will appear immediately. Changes to the core extension will require a restart of the extension host.

Alternatively you can build a .vsix and install it directly in VSCode:

```sh
pnpm vsix
```

A `.vsix` file will appear in the `bin/` directory which can be installed with:

```sh
code --install-extension bin/roo-cline-<version>.vsix
```

### Security Testing

Run comprehensive security tests:

```bash
# Run all security framework tests
npx vitest run src/utils/security/__tests__

# Run MCP security integration tests
npx vitest run src/core/tools/__tests__/useMcpToolTool.security.spec.ts
npx vitest run src/core/tools/__tests__/accessMcpResourceTool.security.spec.ts
```

We use [changesets](https://github.com/changesets/changesets) for versioning and publishing. Check our `CHANGELOG.md` for release notes.

---

## Security Disclaimer

**Rook Code implements comprehensive security controls** including input sanitization, command execution sandboxing, access control, and network security enforcement. However, no security system is perfect. Users should:

- Regularly review security logs and violation reports
- Keep Rook Code updated to receive latest security patches
- Use appropriate security levels for different environments
- Monitor for unusual patterns or attempted attacks
- Report security issues through responsible disclosure

You assume **all risks** associated with the use of any AI coding tools. Rook Code is provided on an **"AS IS"** and **"AS AVAILABLE"** basis with comprehensive security controls but no absolute guarantees.

---

## Contributing

We love community contributions!

When contributing security-related changes:

1. Add comprehensive tests for all security scenarios
2. Include tests for malicious input attempts
3. Test edge cases and boundary conditions
4. Ensure backward compatibility
5. Update security documentation

---

## License

[Apache 2.0 © 2025 Roo Code, Inc.](./LICENSE)

---
