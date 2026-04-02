# Getting Started with MSNGR

This guide walks you through setting up MSNGR from scratch: building, configuring your first mail account, creating agents, setting up policy rules, and connecting an MCP client.

## 1. Build and Initialize

```bash
# Clone and build
make build

# Initialize the database (creates run/msngr.db)
make init

# Copy and edit the config file
cp config.yaml.example run/config.yaml
```

Edit `run/config.yaml` to set your encryption key:

```yaml
encryption_key: "${MSNGR_ENCRYPTION_KEY}"
```

Set the environment variable before starting:

```bash
export MSNGR_ENCRYPTION_KEY="your-secret-key-here"
```

Start the server:

```bash
make run
```

MSNGR is now running at `http://localhost:8600`.

## 2. Create an Operator Account

Open `http://localhost:8600` in your browser. On first run, you'll see a registration form. Create your operator account — this is the admin login for the web UI.

## 3. Add a Mail Server

Navigate to **Email > Servers** and add your IMAP/SMTP server:

- **Name**: A label (e.g. `My Mail Server`)
- **IMAP Host / Port**: Your mail server's IMAP address (e.g. `mail.example.com`, port `993` for TLS)
- **SMTP Host / Port**: Your mail server's SMTP address (e.g. `mail.example.com`, port `465` for implicit TLS or `587` for STARTTLS)
- **TLS**: Enable for both IMAP and SMTP (recommended)

## 4. Add a Mail Account

Navigate to **Email > Accounts** and create an account:

- **Email Address**: The mailbox address (e.g. `assistant@example.com`)
- **Server**: Select the server you just created
- **SMTP Username / Password**: Credentials for sending (usually the email address and its password)
- **Storage Mode**: Controls how much of each message MSNGR keeps locally
  - **Metadata only** — Subject, sender, date, flags (smallest footprint)
  - **Headers** — Metadata plus full headers
  - **Body** — Metadata plus message text and HTML
  - **Full** — Everything including attachments (required for `msngr_download_attachment`)

### Account Options

- **Retrieval enabled** — MSNGR polls this account for new messages via IMAP on a regular interval (default: every 30 seconds)
- **Sending enabled** — Agents can send email through this account via the queue processor
- **Delete retrieved emails from mailbox** — After MSNGR successfully retrieves and stores a message, it deletes the original from the mail server. Use this to keep the remote mailbox clean. Messages are only deleted after they are safely stored in MSNGR's database (and on disk if using body/full storage mode).

## 5. Create an Agent

Navigate to **Agents** and create an agent:

- **Name**: Display name shown in audit logs and as the sender name (e.g. `Claude`)
- **Agent Email**: Select which mail account this agent authenticates with

After creation, click **Renew** to generate an API token. The token is shown once — copy it and store it securely. It's a 64-character hex string.

### Agent Permissions

Permissions are configured in the database and control what each agent can do on each account:

| Capability | Grants |
|---|---|
| `send` | Send email via `msngr_request_send` and `msngr_validate_send` |
| `read` | Read message content via `msngr_read_message` |
| `list` | List and search messages |
| `download_attachment` | Download file attachments from stored messages |

An agent can have permissions on multiple accounts. For example, an agent might have `send + read + list` on its own account and `read + list` on another account for cross-account monitoring.

## 6. Set Up Policy Rules

Navigate to **Rules > Manage**. MSNGR evaluates three policy layers in order:

### Layer A: Config Safety Limits

These are set in `config.yaml` and enforced first. They cannot be changed from the web UI:

```yaml
hard_policy:
  max_message_size_mb: 25
  max_recipients: 50
  deny_domains: []
  forbidden_extensions: [.exe, .bat, .cmd, .scr, .pif, .com, .vbs, .js, .wsf, .msi]
```

- **max_message_size_mb** — Maximum total size of a message including attachments
- **max_recipients** — Maximum number of To + Cc addresses
- **deny_domains** — Domains that agents can never send to (e.g. `["competitor.com"]`)
- **forbidden_extensions** — File extensions blocked on outbound attachments

### Layer C: Operator Rules

These are the rules you create in the web UI. Each rule has:

- **Priority** — Lower number = evaluated first
- **Action** — `allow`, `deny`, or `hold`
- **Match Criteria** — JSON object defining when the rule applies
- **Explanation** — Human-readable reason shown when the rule triggers

**When no rule matches, the default decision is deny** (safe by default).

### Essential Rules to Start With

Here are recommended rules for a typical setup:

**Allow internal mail** (priority 10):
```json
{"domain": "example.com", "action_type": "send"}
```
Action: **allow** — Lets agents send to your own domain without review.

**Hold external mail** (priority 20):
```json
{"action_type": "send"}
```
Action: **hold** — Any outbound mail not caught by a higher-priority rule gets held for operator review. This is your safety net.

**Block sensitive keywords** (priority 5):
```json
{"keywords_present": ["CONFIDENTIAL", "SECRET"], "action_type": "send"}
```
Action: **deny** — Prevents agents from sending messages containing sensitive keywords. Priority 5 ensures this is checked before the allow rule.

**Allow delete for internal messages** (priority 15):
```json
{"domain": "example.com", "action_type": "delete"}
```
Action: **allow** — Lets agents delete messages from your own domain.

### Verifying Rules

Use **Rules > Simulate** to test how a hypothetical action would be evaluated. Enter an agent name, account, action type, recipient, and subject to see which rule matches and what the decision would be. No actual action is performed.

### Match Criteria Reference

| Field | Type | Description |
|---|---|---|
| `action_type` | string | `send`, `read`, `delete`, `mark`, `download_attachment` |
| `domain` | string | Recipient domain (e.g. `example.com`). Supports regex: `"/(gmail\\.com\|yahoo\\.com)/"` |
| `agent_id` | integer | Match a specific agent by ID |
| `keywords_present` | array | Match if subject or body contains any of these strings |
| `max_recipients` | integer | Match if recipient count exceeds this |
| `attachment_present` | boolean | Match if the message has attachments |

## 7. Connect an MCP Client

MSNGR's MCP endpoint is at `http://localhost:8600/mcp`. Configure your MCP client to connect to this URL.

### Authentication Flow

```
msngr_login(login_email, token)
  -> msngr_list_accounts()
  -> msngr_select_account(account_id)
  -> ... use account-scoped tools ...
```

### Sending Email

```
msngr_request_send(to, subject, body_text)
```

The message goes through policy evaluation:
- **allow** — Queued for delivery (typically sent within 10 seconds)
- **hold** — Paused for operator review (check Operations > Holds in the web UI)
- **deny** — Blocked with an explanation

### Sending Attachments

```json
{
  "to": "colleague@example.com",
  "subject": "Monthly report",
  "body_text": "Please find the report attached.",
  "attachments": [
    {
      "filename": "report.pdf",
      "mime_type": "application/pdf",
      "content_base64": "JVBERi0xLjQK..."
    }
  ]
}
```

Attachments are base64-encoded in the request. The policy engine checks file extensions against the forbidden list in `config.yaml` — attempting to send a `.exe` or other blocked type will be denied at Layer A.

### Reading and Downloading

```
msngr_list_messages(folder: "INBOX")
msngr_read_message(message_id: 42)
msngr_download_attachment(message_id: 42, filename: "report.pdf")
```

Downloading attachments requires the `download_attachment` capability and the account must use `full` storage mode.

## 8. Monitor Operations

- **Operations > Queue** — Watch outbound messages move through the delivery lifecycle
- **Operations > Holds** — Review and release/deny held messages
- **Operations > Audit** — Full trail of every agent and operator action
- **Dashboard** — Overview of accounts, agents, rules, queue depth, pending holds, and audit events

## Next Steps

- [MCP API Reference](MCP_API.md) — Complete tool reference with parameters and response shapes
- [Agent Guide](AGENTS.md) — Detailed agent setup and usage patterns
- [Specifications](SPECIFICATIONS.md) — Full product and architecture spec
- [Testing](TESTING.md) — End-to-end test suite
