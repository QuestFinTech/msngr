<p align="center">
  <img src="docs/msngr.png" alt="MSNGR" width="200">
</p>

<h1 align="center">MSNGR</h1>

<p align="center"><strong>Mail Secure Network Gateway Relay — policy-enforced mail gateway for MCP agents and human operators.</strong></p>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](https://go.dev)

---

## What is MSNGR?

MSNGR mediates between MCP agents, operators (via web UI), and external mail infrastructure (IMAP/SMTP). It is not a general-purpose mail client — it is a controlled mediation layer with strong policy enforcement, auditability, and least-privilege access.

- **Policy engine** — 3-layer evaluation: config safety limits → operator-defined rules → runtime controls
- **MCP interface** — 15 tools for agents to list, read, search, send, and manage email
- **Operator web UI** — Dashboard, mail server/account config, agent management, rule CRUD, queue/hold operations, audit trail
- **Agent authentication** — API token auth with per-account permission scoping
- **Safe by default** — Deny decision when no rule matches; outbound mail goes through queue, never fire-and-forget
- **Auditability** — Structured audit logging for all agent and operator actions
- **Single binary** — No external dependencies beyond SQLite; embeds templates, migrations, and static assets

---

## Quick Start

```bash
# Build
make build

# Initialize database
make init

# Start server on :8600
make run
```

The operator web UI is available at `http://localhost:8600`. On first run, you'll be prompted to create an operator account.

## Requirements

- Go 1.26+
- SQLite 3
- An IMAP/SMTP mail server for email connectivity

For cross-compilation and release builds, see [docs/BUILDING.md](docs/BUILDING.md).

## Tech Stack

- **Language**: Go (stdlib only — no external web or CLI frameworks)
- **Database**: SQLite (WAL mode) — metadata only
- **Message storage**: Filesystem tar.gz archives (body + attachments)
- **Config**: YAML bootstrap (`config.yaml`) + dynamic rules in SQLite
- **Protocols**: IMAP (go-imap/v2), SMTP (net/smtp)
- **Auth**: Operator login (bcrypt), Agent API tokens (SHA-256 hashed)
- **Templates**: Go html/template with embedded CSS

## Policy Model

| Layer | Source | Purpose |
|-------|--------|---------|
| **Config** | `config.yaml` | Safety limits: max message size, max recipients, forbidden extensions, deny domains |
| **Rules** | SQLite / Web UI | Operator-defined rules with JSON match criteria, priority ordering, allow/deny/hold actions |
| **Runtime** | In-memory | Temporary states: rate limits, one-time approvals |

Default decision when no rule matches: **deny**.

## MCP Tools

MSNGR exposes an MCP endpoint at `POST /mcp` with Bearer token authentication.

| Category | Tools |
|----------|-------|
| **Inbound** | `msngr_list_messages`, `msngr_read_message`, `msngr_search_messages` |
| **Outbound** | `msngr_request_send`, `msngr_validate_send` |
| **Actions** | `msngr_mark_message`, `msngr_delete_message`, `msngr_download_attachment` |
| **Session** | `msngr_select_account` |
| **Admin** | `msngr_list_holds`, `msngr_review_hold`, `msngr_explain_decision`, `msngr_list_accounts`, `msngr_test_account_connectivity` |

## CLI

```
msngr run               Start gateway service
msngr init              Create database schema
msngr doctor            Check config, DB, account health
msngr config check      Validate configuration file
msngr rule simulate     Test a hypothetical action against policies
msngr export audit      Export audit events (JSON/CSV)
msngr version           Print version information
```

## Configuration

Copy `config.yaml.example` to `run/config.yaml` and adjust:

```yaml
listen: ":8600"
db:
  path: ./msngr.db
storage_path: ./storage
encryption_key: "${MSNGR_ENCRYPTION_KEY}"
hard_policy:
  max_message_size_mb: 25
  max_recipients: 50
  deny_domains: []
  forbidden_extensions: [.exe, .bat, .cmd, .scr, .pif, .com, .vbs, .js, .wsf, .msi]
```

See `config.yaml.example` for all options.

## Project Structure

```
cmd/msngr/              CLI entrypoint
internal/
  config/               YAML bootstrap config
  db/                   SQLite connection, migrations, queries
  model/                Domain types
  policy/               3-layer policy engine
  imap/                 IMAP adapter and polling
  smtp/                 SMTP adapter (STARTTLS + implicit TLS)
  queue/                Outbound queue processor
  mcp/                  MCP tool handlers
  web/                  Operator web UI
  audit/                Structured audit logging
  storage/              Filesystem message archives
```

## Documentation

- [Getting Started](docs/GETTING_STARTED.md) — First-time setup: accounts, agents, rules, and connecting an MCP client
- [Agent Guide](docs/AGENTS.md) — Setting up and using MCP agents
- [MCP API Reference](docs/MCP_API.md) — Complete tool reference with parameters and responses
- [Building](docs/BUILDING.md) — Cross-compilation and release builds
- [Specifications](docs/SPECIFICATIONS.md) — Product and architecture spec
- [Testing](docs/TESTING.md) — End-to-end test suite

## License

See [LICENSE](LICENSE).
