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

- **Policy enforcement**: Layered policy engine with safe-by-default deny decision
- **Least privilege**: Each agent action checks its own capability on the selected account. Selecting an account grants nothing by itself, and holding one capability does not imply another
- **Separation of review**: Approving a held message needs the `review_hold` capability, which is never granted automatically, and an agent can never release a message it queued itself
- **Content Security Policy**: CSP nonce per request, security headers
- **Input validation**: Server-side validation on all inputs
- **Parameterized queries**: All database queries use parameterized statements
- **Password policy**: Operator passwords hashed with bcrypt
- **Token security**: Agent API tokens stored as SHA-256 hashes, shown once on creation
- **Session management**: Operator cookies are HMAC-signed and expiry is enforced server-side; MCP agent sessions have configurable timeouts
- **Audit logging**: Authentication, policy decisions, delivery outcomes, hold reviews, account health transitions, and entity changes are logged
- **Queue enforcement**: Outbound mail always goes through the queue — no direct send
- **Encryption at rest**: Mail account credentials are encrypted with AES-256-GCM under a scrypt-derived key from `encryption_key`, which is held outside the database
- **MCP authentication**: Bearer token auth on all MCP endpoints

### Known limitations

Worth knowing before you deploy — these are design gaps, not vulnerabilities to report:

- **No rate limiting on agent actions.** Layer D of the specification (rate limits, temporary blocks) is not implemented. An authenticated agent can call tools as fast as it likes, subject only to policy rules. The one exception is `msngr_poll_account`, which is rate-limited because it reaches out to a third-party mail server.
- **`encryption_key` has no rotation path.** Changing it makes existing stored credentials undecryptable; they must be re-entered per account in the web UI.
- **Credentials are decryptable by the running process.** Encryption at rest protects a stolen database file, not a compromised host — the key is in the process environment.
- **Message bodies are stored unencrypted** on the filesystem when the account's storage mode is `body` or `full`. Use filesystem permissions or disk encryption if that matters for your deployment.
