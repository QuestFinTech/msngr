# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MSNGR, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report via email to the repository maintainers. Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours of receipt
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity; critical issues are prioritized

## Scope

The following are in scope:

- Authentication and authorization bypass
- Cross-site scripting (XSS) and cross-site request forgery (CSRF)
- SQL injection
- MCP protocol security (JSON-RPC validation, tool authorization)
- Session management vulnerabilities
- Privilege escalation (cross-account access, role bypass)
- Policy engine bypass (circumventing deny/hold decisions)
- Denial of service via resource exhaustion

The following are out of scope:

- Vulnerabilities in dependencies (report to the upstream project)
- Social engineering attacks
- Denial of service via network flooding (infrastructure concern)
- Issues requiring physical access to the server

## Supported Versions

Security fixes are applied to the latest release only. We recommend always running the most recent version.

## Security Measures

MSNGR includes several built-in security measures:

- **Policy enforcement**: 3-layer policy engine with safe-by-default deny decision
- **Content Security Policy**: CSP nonce per request, security headers
- **Input validation**: Server-side validation on all inputs
- **Parameterized queries**: All database queries use parameterized statements
- **Password policy**: Operator passwords hashed with bcrypt
- **Token security**: Agent API tokens stored as SHA-256 hashes, shown once on creation
- **Session management**: Configurable session timeouts for operators and MCP agents
- **Audit logging**: All authentication, policy decisions, and entity changes are logged
- **Queue enforcement**: Outbound mail always goes through the queue — no direct send
- **Encryption**: Mail server credentials encrypted at rest
- **MCP authentication**: Bearer token auth on all MCP endpoints
