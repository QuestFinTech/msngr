# Agent Guide

This guide covers how to set up and use MCP agents with MSNGR.

## Overview

An agent is an automated MCP client (e.g., Claude, a custom bot) that interacts with email through MSNGR's policy-enforced gateway. Agents authenticate with API tokens, operate on permitted mail accounts, and are subject to the same policy rules as any other action in the system.

## Setting Up an Agent

### 1. Create the Agent (Operator Web UI)

Navigate to **Agents** in the web UI and create a new agent:

- **Agent Email** — The agent's identity (e.g., `claude@example.com`). Must be unique. This is the login identity, not necessarily a real mailbox.
- **Display Name** — Human-readable name (e.g., `Claude`). Must be unique. Used in audit logs.

### 2. Create an API Token

On the agent's detail page, click **Create Token**. The token is a 64-character hex string shown **once** — copy it immediately. It is stored as a SHA-256 hash and cannot be recovered.

Example token: `ba72bb0050b2605b8b087ba48894526c94806b0780cabbcb728f7e26f8ef4f3d`

### 3. Grant Account Permissions

Agents have no access by default. An operator must explicitly grant permissions for each mail account the agent should access.

Navigate to the agent's page and add permissions:

| Capability | Grants |
|---|---|
| `read` | List, search, read, mark and delete messages, and trigger a poll |
| `send` | Queue outbound email from the account (subject to policy) |
| `download_attachment` | Download file attachments from stored messages |
| `review_hold` | Approve or reject held messages. Not granted by default — see below |

Permissions are per-account. An agent can have different capabilities on different accounts (e.g., send on account 1 but read-only on account 2). Each capability is checked independently: holding one does not imply another, so a send-only agent cannot read the mailbox it sends from.

Creating an agent whose address matches an existing account auto-grants `read`, `send` and `download_attachment` on it. `review_hold` is never granted automatically: held messages are meant for a human to release, and an agent may never review a message it queued itself even if the capability is granted.

## Connecting to MSNGR

### MCP Configuration

Point your MCP client at the MSNGR endpoint:

```json
{
  "mcpServers": {
    "msngr": {
      "type": "streamableHttp",
      "url": "http://localhost:8600/mcp"
    }
  }
}
```

No `Authorization` header is needed in the config — the agent authenticates at runtime via `msngr_login`.

### Authentication

Call `msngr_login` as the first tool invocation:

```
msngr_login(login_email: "claude@example.com", token: "<your-token>")
```

On success, the MCP session is authenticated for all subsequent calls. The session persists until it expires (configurable via Settings, default 60 minutes).

**Bearer token fallback:** For backward compatibility, you can also authenticate by including `Authorization: Bearer <token>` in the HTTP headers of every request. This creates a session automatically on first use.

### Account Selection

After login, select which mail account to operate on:

```
msngr_list_accounts()       → see which accounts you can access
msngr_select_account(account_id: 1)  → activate account 1 for this session
```

You can switch accounts at any time by calling `msngr_select_account` again.

## Common Workflows

### Reading Email

```
msngr_select_account(account_id: 1)
msngr_list_messages(folder: "INBOX", limit: 20)
msngr_read_message(message_id: 42)
msngr_search_messages(query: "quarterly report")
```

`msngr_list_messages` returns retrieval state alongside the messages, including
`last_polled_at`. An empty inbox is only meaningful next to that timestamp — if the
gateway has not polled recently, call `msngr_poll_account()` to retrieve now rather
than waiting for the next cycle. It is rate-limited to one poll per account every
10 seconds.

Requesting a folder MSNGR holds nothing for returns `FOLDER_NOT_RETRIEVED` together
with the folders that do have messages, rather than an empty list. Delivered outbound
mail is filed under the account's Sent folder, whose name is server-dependent and
often `INBOX.Sent`.

### Sending Email

All outbound email is policy-evaluated. Messages are never sent directly — they go through the outbound queue.

```
msngr_select_account(account_id: 1)

# Dry-run: check what policy would decide
msngr_validate_send(to: "colleague@example.com", subject: "Update", body_text: "...")

# Actually send (queues the message)
msngr_request_send(to: "colleague@example.com", subject: "Update", body_text: "...")
```

Possible outcomes:
- **queued** — Policy allowed the message. It enters the outbound queue for delivery.
- **held** — Policy flagged the message for operator review. An operator must approve it before it sends.
- **denied** — Policy blocked the message. Check the `matched_rule` and `suggestion` in the response.

All three return a `correlation_id`.

**`queued` is not `sent`.** Delivery happens asynchronously. To find out whether the
message was actually transmitted, use the `queue_id` from the response:

```
msngr_queue_status(queue_id: 7)
```

It reports the current state (`queued`, `sending`, `sent`, `failed`, `held`,
`rejected`, `cancelled`), what that state means, the attempt count, and the SMTP
server's own reply for the last attempt. Do not infer delivery from the absence of an
error — check.

### Understanding Policy Decisions

```
# After a send, use the correlation_id from the response
msngr_explain_decision(correlation_id: "abc-123-def")
```

This returns the audit trail showing which policy layers were evaluated and which rule matched.

### Managing Messages

```
msngr_mark_message(message_id: 42, flag: "read")
msngr_delete_message(message_id: 42)          # subject to policy
msngr_download_attachment(message_id: 42, filename: "report.pdf")
```

### Reviewing Holds (rarely available to agents)

`msngr_list_holds` shows held messages on accounts the agent can access:

```
msngr_list_holds(status: "pending")
```

Releasing one is a different matter. `msngr_review_hold` requires the `review_hold`
capability, which is never granted automatically, and an agent can never review a
message it queued itself — that returns `SELF_REVIEW_FORBIDDEN` regardless of
capabilities. Holds exist so that a person decides; in most deployments they are
resolved by an operator in the web UI, and an agent calling this tool should expect
`ACCESS_DENIED`.

```
msngr_review_hold(hold_id: 3, action: "approve")
```

### Checking Connectivity

```
msngr_test_account_connectivity(account_id: 1)
```

Returns IMAP and SMTP reachability status for the account's mail server.

## Policy Model

Every agent action passes through two policy layers:

1. **Config layer (Layer A)** — Hard safety limits from `config.yaml`: max message size, max recipients, forbidden file extensions, denied domains, plus mandatory agent identity and the `send` capability. Always enforced first. Cannot be overridden by rules.

2. **Rules layer (Layer C)** — Operator-defined rules with JSON match criteria. Rules have priorities (lower number = higher priority) and can `allow`, `deny`, or `hold` an action. Matched in priority order; first match wins.

**Default decision: deny.** If no rule matches an action, it is blocked. Operators must create explicit allow rules for the actions agents should be able to perform.

The specification also describes a Layer B (static YAML policy) and Layer D (runtime state such as rate limits and one-time approvals). Neither is implemented — **agent actions are not rate-limited**.

## Session Lifecycle

- Sessions are created by `msngr_login` (or implicitly by Bearer token auth).
- Session timeout is configurable (default: 60 minutes). Adjustable via Settings in the web UI.
- On expiry, any tool call returns `SESSION_EXPIRED`. The agent must call `msngr_login` again.
- Account selection is per-session and resets on re-authentication.

## Security Notes

- Tokens are shown once on creation and stored as SHA-256 hashes. Treat them like passwords.
- An agent can only access accounts it has explicit permissions for.
- All agent actions are audit-logged with the agent's numeric identity, action, outcome, and timestamp. Sends additionally record their delivery outcome, recipients and the SMTP server's reply under the same correlation ID.
- Outbound email always goes through the queue — agents cannot bypass policy or send directly.
- Each capability is checked independently. Selecting an account proves only that the agent has some grant on it: `read` does not imply `send`, `send` does not imply `read`, and `download_attachment` is separate from both — reading a message does not grant access to its attachments.
