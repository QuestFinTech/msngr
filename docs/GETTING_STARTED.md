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

This key encrypts mail account credentials at rest. Two things follow from that:

- **Keep it.** Changing the key makes stored credentials undecryptable, and each account's credentials have to be re-entered in the web UI. There is no rotation path.
- **Leaving it unset is allowed but not advised.** MSNGR starts, warns at boot, and stores credentials in cleartext. Setting the key later encrypts existing credentials on the next start. `msngr doctor` reports which state you are in.

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

An API token is generated when the agent is created. The token is shown once — copy it and store it securely. It's a 64-character hex string. Use **Renew** later to revoke the existing token and issue a new one.

### Agent Permissions

Permissions are granted per account from the agent's row in the web UI, and control what each agent can do on each account:

| Capability | Grants |
|---|---|
| `read` | List, search, read, mark and delete messages, and trigger a poll |
| `send` | Send email via `msngr_request_send` and `msngr_validate_send` |
| `download_attachment` | Download file attachments from stored messages |
| `review_hold` | Approve or reject held messages. Never granted automatically |

If the agent's email address matches an existing account, `read`, `send` and `download_attachment` are granted on it automatically at creation. Everything else is explicit.

Each capability is checked on its own: holding `send` does not imply `read`, so a send-only agent cannot read the mailbox it sends from. An agent can have different capabilities on different accounts — for example `read + send` on its own account and `read` only on another for cross-account monitoring.

`review_hold` deserves a second thought before granting it. Holds exist so that a person decides; an agent that can release held mail turns the hold into a delay. Even with the capability, an agent can never review a message it queued itself.

## 6. Set Up Policy Rules

Navigate to **Rules > Manage**. MSNGR evaluates two policy layers in order:

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

**Block a sensitive keyword** (priority 5):
```json
{"keywords_present": ["CONFIDENTIAL"], "action_type": "send"}
```
Action: **deny** — Prevents agents from sending messages containing the keyword. Priority 5 ensures this is checked before the allow rule.

Note that `keywords_present` requires **every** listed keyword to appear. `["CONFIDENTIAL", "SECRET"]` matches only a message containing both words, which is rarely what you want — use one rule per keyword to block either.

**Allow deletion on a specific account** (priority 15):
```json
{"action_type": "delete", "account_id": 1}
```
Action: **allow** — Lets agents delete messages on account 1. Without a matching rule, deletion falls through to the default deny.

Only `action_type`, `account_id` and `agent_id` are usable for non-send actions. Deleting, marking and reading evaluate the agent, the account and the verb — the message's addresses, subject and body are not part of the evaluation, so `domain`, `recipient`, `sender` and the keyword criteria never match a `delete` rule.

### Verifying Rules

Use **Rules > Simulate** to test how a hypothetical action would be evaluated. Enter an agent name, account, action type, recipient, and subject to see which rule matches and what the decision would be. No actual action is performed.

### Match Criteria Reference

A rule matches when **every** field present in its criteria matches. An empty criteria object `{}` matches everything.

| Field | Type | Matches when |
|---|---|---|
| `action_type` | string | The action is exactly this: `send`, `read`, `delete`, `mark`, `download_attachment` |
| `agent_id` | string | The agent's **display name** equals this. Despite the field name it is not a numeric ID — `{"agent_id": "Claude"}` |
| `account_id` | integer | The action is on this account ID |
| `sender` | string | The From address matches. Exact and case-insensitive, or regex if wrapped in slashes |
| `recipient` | string | Any To or Cc address matches. Exact or regex, as above |
| `domain` | string | Any recipient's domain matches. Exact or regex: `"/(gmail\\.com\|yahoo\\.com)/"` |
| `keywords_present` | array | Subject or body contains **all** of these strings (case-insensitive) |
| `keywords_absent` | array | Subject or body contains **none** of these strings |
| `attachment_present` | boolean | The message has attachments (`true`) or has none (`false`) |
| `attachment_types` | array | At least one attachment matches one of these MIME types or extensions (e.g. `[".pdf", "image/png"]`) |
| `max_size` | integer | The message is **at most** this many bytes |
| `max_recipients` | integer | There are **at most** this many To + Cc recipients |

`max_size` and `max_recipients` are upper bounds on when the rule *applies*, not thresholds that trigger it. `{"max_recipients": 5, "action_type": "send"}` with action `allow` means "allow sends to five recipients or fewer" — a six-recipient send does not match the rule and falls through to the default deny. To block large sends outright, set the corresponding limit in `hard_policy`, which is enforced at Layer A.

Regex patterns are wrapped in forward slashes and matched case-insensitively. An invalid pattern never matches.

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

All three outcomes return a `correlation_id` you can pass to `msngr_explain_decision`.

**`queued` does not mean sent.** It means policy passed and the gateway will attempt delivery. Confirm the outcome with the `queue_id` from the response:

```
msngr_queue_status(queue_id: 7)
```

This reports `sent`, `failed`, `held` or still `queued`, along with the SMTP server's own reply and the attempt count. A delivered message also leaves a `send_completed` audit event under the same correlation ID; a failed one leaves `send_failed`.

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

MSNGR polls INBOX on an interval, so an empty result may just mean it has not looked yet. `msngr_list_messages` reports `last_polled_at` alongside the results, and `msngr_poll_account()` forces a retrieval now rather than waiting for the next cycle.

Delivered outbound mail is filed under the account's Sent folder — usually named `INBOX.Sent` rather than `Sent`, depending on the server. `msngr_list_messages` names the folders that hold messages when you ask for one that does not.

## 8. Monitor Operations

- **Operations > Queue** — Watch outbound messages move through the delivery lifecycle
- **Operations > Holds** — Review and release/deny held messages
- **Operations > Audit** — Full trail of every agent and operator action
- **Dashboard** — Configuration totals plus a Usage section: mail received and sent, delivery rate, holds and denials over a 7/30/90-day window, a daily volume chart, per-account and per-agent activity, and storage consumption
- **Health endpoint** — `GET /health` needs no authentication and returns HTTP 503 when any account is unhealthy, naming the affected accounts, their last error and how long they have been failing. Point a monitoring probe at it; a broken mailbox is otherwise easy to miss for weeks

### Not yet implemented

Two things on the Settings page do not do anything yet, and are worth knowing before you rely on them:

- **Retention periods** are stored but nothing prunes on them. Messages, archives, audit events and queue rows accumulate indefinitely.
- **`ticks.maintenance_ms`** in `config.yaml` configures the cleanup interval for that same absent job.

Storage growth therefore needs watching — the Dashboard's Storage panel is the place to do it.

## Next Steps

- [MCP API Reference](MCP_API.md) — Complete tool reference with parameters and response shapes
- [Agent Guide](AGENTS.md) — Detailed agent setup and usage patterns
- [Specifications](SPECIFICATIONS.md) — Full product and architecture spec
- [Testing](TESTING.md) — End-to-end test suite
