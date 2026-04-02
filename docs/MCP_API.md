# MCP API Reference

## Transport

- **Protocol:** JSON-RPC 2.0 via MCP Streamable HTTP
- **Endpoint:** `POST /mcp`
- **SDK:** `github.com/modelcontextprotocol/go-sdk/mcp`

## Authentication

Two authentication methods are supported:

**Session-based (recommended):** Call `msngr_login` as the first tool invocation. The MCP session is authenticated for all subsequent calls until timeout.

**Bearer token (fallback):** Include `Authorization: Bearer <token>` in HTTP headers on every request. A session is created automatically on first use.

Sessions expire after a configurable timeout (default: 60 minutes, adjustable via Settings). Expired sessions return `SESSION_EXPIRED`.

## Response Envelope

Every tool returns a JSON object with this shape:

```json
{
  "ok": true,
  "message": "human-readable status",
  "data": {},
  "error_code": "CODE",
  "matched_rule": "rule name",
  "correlation_id": "uuid",
  "suggestion": "hint for the caller",
  "retryable": false
}
```

Fields are omitted when not applicable. `error_code` and `retryable` only appear on failure. `matched_rule`, `correlation_id`, and `suggestion` only appear on policy-evaluated actions.

## Error Codes

| Code | Meaning |
|---|---|
| `AUTHENTICATION_REQUIRED` | No valid token or session |
| `AUTHENTICATION_FAILED` | Wrong credentials in `msngr_login` |
| `SESSION_EXPIRED` | Session exceeded timeout |
| `INVALID_PARAMS` | Missing or invalid parameter |
| `NO_ACCOUNT_SELECTED` | Account-scoped tool called before `msngr_select_account` |
| `NOT_FOUND` | Resource does not exist |
| `ACCESS_DENIED` | Permission or capability check failed |
| `ACCOUNT_DISABLED` | Selected account is disabled |
| `POLICY_DENIED` | Policy engine denied the action |
| `ATTACHMENT_NOT_AVAILABLE` | Attachment not in filesystem storage |
| `INTERNAL_ERROR` | Server-side error |

## Required Workflow

```
msngr_login
  -> msngr_list_accounts
  -> msngr_select_account
  -> <account-scoped tools>
```

`msngr_list_holds`, `msngr_review_hold`, `msngr_explain_decision`, `msngr_list_accounts`, and `msngr_test_account_connectivity` do not require an account to be selected.

---

## Tools

### msngr_login

Authenticate with the gateway. Must be called before any other tool (unless using Bearer token auth).

**Auth:** None

| Parameter | Type | Required | Description |
|---|---|---|---|
| `login_email` | string | yes | Agent email address |
| `token` | string | yes | API token (64-char hex) |

**Response data:**
```json
{
  "agent_id": 1,
  "display_name": "Claude",
  "agent_email": "claude@sys.lu"
}
```

---

### msngr_list_accounts

List mail accounts the agent has permission to access.

**Auth:** Required | **Account:** Not required

| Parameter | Type | Required | Description |
|---|---|---|---|
| *(none)* | | | |

**Response data:** Array of account objects:
```json
[{
  "id": 1,
  "name": "Main Inbox",
  "email_address": "inbox@example.com",
  "retrieval_enabled": true,
  "sending_enabled": true,
  "storage_mode": "full",
  "enabled": true,
  "health_status": "ok"
}]
```

---

### msngr_select_account

Select a mail account for the current session.

**Auth:** Required | **Account:** Not required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `account_id` | integer | yes | Account ID from `msngr_list_accounts` |

**Response data:**
```json
{
  "account_id": 1,
  "account_name": "Main Inbox",
  "email_address": "inbox@example.com"
}
```

**Errors:** `ACCESS_DENIED` if agent has no permissions on the account. `ACCOUNT_DISABLED` if the account is disabled.

---

### msngr_list_messages

List messages in a mail folder.

**Auth:** Required | **Account:** Required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `folder` | string | no | Folder name (default: `INBOX`) |
| `limit` | integer | no | Max messages to return (default: 50) |

**Response data:** Array of message objects:
```json
[{
  "id": 42,
  "account_id": 1,
  "message_id": "<rfc-id@domain>",
  "folder": "INBOX",
  "from_addr": "sender@example.com",
  "to_addrs": "[\"me@example.com\"]",
  "cc_addrs": "[]",
  "subject": "Hello",
  "date": "2025-01-01T12:00:00Z",
  "size": 4096,
  "direction": "inbound",
  "stored_on_disk": false,
  "is_read": false,
  "is_flagged": false
}]
```

---

### msngr_read_message

Read a message including body text and HTML.

**Auth:** Required | **Account:** Required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `message_id` | integer | yes | Message ID |

**Response data:**
```json
{
  "message": { },
  "body_text": "plain text body",
  "body_html": "<html>...</html>"
}
```

`body_html` may be empty if not stored. Body content requires `stored_on_disk == true` (account storage mode `body` or `full`).

---

### msngr_search_messages

Search messages by subject, sender, or recipient.

**Auth:** Required | **Account:** Required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string | yes | Search query |
| `limit` | integer | no | Max results (default: 50) |

**Response data:** Array of message objects (same shape as `msngr_list_messages`).

---

### msngr_request_send

Send an email. The message is policy-evaluated and then queued or held — never sent directly.

**Auth:** Required | **Account:** Required | **Capability:** `send`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `to` | string | yes | Comma-separated recipient addresses |
| `subject` | string | yes | Subject line |
| `body_text` | string | yes | Plain text body |
| `body_html` | string | no | HTML body |
| `cc` | string | no | Comma-separated CC addresses |
| `attachments` | array | no | File attachments (see below) |

**Attachments** — each element is an object:

| Field | Type | Required | Description |
|---|---|---|---|
| `filename` | string | yes | Filename with extension (e.g. `report.pdf`) |
| `content_base64` | string | yes | File content encoded as base64 |
| `mime_type` | string | no | MIME type (defaults to `application/octet-stream`) |

Example:
```json
{
  "to": "recipient@example.com",
  "subject": "Report",
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

Attachments are evaluated by the policy engine — forbidden file extensions (`.exe`, `.bat`, etc.) configured in `config.yaml` will cause the send to be denied at Layer A.

**Policy outcomes:**

- **allow** — Message queued for delivery.
  ```json
  { "ok": true, "data": { "queue_id": 7, "status": "queued" }, "correlation_id": "..." }
  ```

- **hold** — Message held for operator review.
  ```json
  { "ok": true, "data": { "queue_id": 7, "status": "held" }, "matched_rule": "...", "correlation_id": "..." }
  ```

- **deny** — Message blocked.
  ```json
  { "ok": false, "error_code": "POLICY_DENIED", "matched_rule": "...", "suggestion": "..." }
  ```

**Pre-conditions:** Account must have `sending_enabled == true`. Agent must have `send` capability on the account.

---

### msngr_validate_send

Dry-run policy evaluation for a send request without queuing the message.

**Auth:** Required | **Account:** Required | **Capability:** `send`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `to` | string | yes | Comma-separated recipient addresses |
| `subject` | string | yes | Subject line |
| `body_text` | string | yes | Plain text body |
| `cc` | string | no | Comma-separated CC addresses |

**Response data:**
```json
{
  "outcome": "allow",
  "explanation": "reason text",
  "matched_rules": []
}
```

`ok` is always `true` on successful evaluation, even if the outcome is `deny` — this is a diagnostic tool.

---

### msngr_mark_message

Mark a message with a flag.

**Auth:** Required | **Account:** Required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `message_id` | integer | yes | Message ID |
| `flag` | string | yes | `read`, `unread`, or `flagged` |

**Response data:**
```json
{ "message_id": 42, "flag": "read" }
```

---

### msngr_delete_message

Delete a message. Subject to policy evaluation (action type `delete`).

**Auth:** Required | **Account:** Required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `message_id` | integer | yes | Message ID |

**Response data:**
```json
{ "message_id": 42 }
```

Returns `POLICY_DENIED` if the policy engine denies the delete action.

---

### msngr_download_attachment

Download a file attachment from a stored message.

**Auth:** Required | **Account:** Required | **Capability:** `download_attachment`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `message_id` | integer | yes | Message ID |
| `filename` | string | yes | Attachment filename |

**Response data:**
```json
{
  "filename": "report.pdf",
  "data": "<base64>",
  "encoding": "base64",
  "size": 102400
}
```

Requires the message to have `stored_on_disk == true` (account storage mode `full`).

---

### msngr_list_holds

List messages held for operator review.

**Auth:** Required | **Account:** Not required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `status` | string | no | Filter: `pending` (default), `approved`, `rejected` |

**Response data:** Array of hold objects:
```json
[{
  "id": 3,
  "queue_id": 7,
  "rule_id": 2,
  "reason": "matched hold rule: external domain",
  "status": "pending",
  "reviewer_id": null,
  "reviewed_at": null,
  "created_at": "..."
}]
```

---

### msngr_review_hold

Approve or reject a held message.

**Auth:** Required | **Account:** Not required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `hold_id` | integer | yes | Hold ID from `msngr_list_holds` |
| `action` | string | yes | `approve` or `reject` |

**Response data:**
```json
{ "hold_id": 3, "action": "approve" }
```

Approved messages are released to the outbound queue. Rejected messages are discarded.

---

### msngr_explain_decision

Retrieve the audit trail for a policy decision.

**Auth:** Required | **Account:** Not required

| Parameter | Type | Required | Description |
|---|---|---|---|
| `correlation_id` | string | yes | Correlation ID from `msngr_request_send` |

**Response data:** Array of audit event objects:
```json
[{
  "id": 100,
  "actor_type": "agent",
  "actor_id": "Claude",
  "action": "send_requested",
  "target_type": "outbound",
  "target_id": "7",
  "outcome": "success",
  "details_json": "...",
  "correlation_id": "abc-123",
  "created_at": "..."
}]
```

---

### msngr_test_account_connectivity

Test IMAP and SMTP connectivity for a mail account (5-second TCP dial timeout).

**Auth:** Required | **Account:** Not required (takes explicit `account_id`)

| Parameter | Type | Required | Description |
|---|---|---|---|
| `account_id` | integer | yes | Account ID to test |

**Response data:**
```json
{
  "account_id": 1,
  "account": "Main Inbox",
  "imap": { "ok": true, "address": "mail.example.com:993" },
  "smtp": { "ok": true, "address": "mail.example.com:587" }
}
```

Individual protocol failures are reported inside `data` (e.g., `{"ok": false, "error": "connection failed"}`), not as a top-level error. Requires the agent to have any permission on the account.

---

## Permissions

Agent access is controlled per-account via capabilities:

| Capability | Required by |
|---|---|
| *(any)* | `msngr_select_account` (any permission entry grants access) |
| `send` | `msngr_request_send`, `msngr_validate_send` |
| `download_attachment` | `msngr_download_attachment` |

`msngr_list_messages`, `msngr_read_message`, `msngr_search_messages`, `msngr_mark_message`, and `msngr_delete_message` require an account to be selected but no specific capability beyond the initial account mapping.

## Outbound Message Lifecycle

```
draft_requested -> queued -> sending -> sent
                         \-> held -> approved -> queued -> sending -> sent
                         \-> held -> rejected
                         \-> failed
                         \-> cancelled
```

All outbound mail passes through the queue processor. The queue runs on a configurable tick interval (`config.yaml` `ticks.queue_process_ms`, default 10 seconds).
