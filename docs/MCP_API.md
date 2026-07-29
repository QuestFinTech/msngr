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

`data` and `details` carry different things. `data` is the answer to the request — the messages, the account, the queue item. `details` is context about the answer: how many results, which folder, when the account was last polled. List tools always return an array in `data`, empty when there is nothing to return; `null` is never used to mean "none".

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
| `FOLDER_NOT_RETRIEVED` | No messages are stored in that folder; the response lists the folders that do have some |
| `SELF_REVIEW_FORBIDDEN` | An agent tried to review a hold for a message it queued |
| `ALREADY_REVIEWED` | The hold has already been approved or rejected |
| `POLL_TOO_SOON` | `msngr_poll_account` called inside the rate-limit window |
| `POLL_FAILED` | Retrieval was attempted and failed |
| `NOT_SUPPORTED` | The gateway process is not running retrieval, so it cannot poll on demand |
| `INTERNAL_ERROR` | Server-side error |

## Required Workflow

```
msngr_login
  -> msngr_list_accounts
  -> msngr_select_account
  -> <account-scoped tools>
```

`msngr_list_holds`, `msngr_review_hold`, `msngr_queue_status`, `msngr_explain_decision`, `msngr_list_accounts`, and `msngr_test_account_connectivity` do not require an account to be selected. They are still scoped to the accounts the agent holds a permission on.

Selecting an account is not authorization. It establishes which account the
account-scoped tools operate on; each of those tools then checks its own capability.

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
  "server_id": 1,
  "server_name": "Main Mail Server",
  "smtp_host": "smtp.example.com",
  "smtp_port": 465,
  "imap_host": "imap.example.com",
  "imap_port": 993,
  "retrieval_enabled": true,
  "sending_enabled": true,
  "delete_after_retrieval": true,
  "storage_mode": "full",
  "enabled": true,
  "health_status": "ok",
  "last_polled_at": "2026-07-29T19:09:58Z"
}]
```

`delete_after_retrieval` is worth reading before assuming mail stays on the server: when it is true, MSNGR removes each message from the mailbox once it has stored it, so it cannot be re-fetched or read from another client.

`health_changed_at`, `health_error` and `last_polled_at` are omitted when empty.

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

**Auth:** Required | **Account:** Required | **Capability:** `read`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `folder` | string | no | Folder name (default: `INBOX`) |
| `limit` | integer | no | Max messages to return (default: 50) |

**Response data:** Array of message objects (empty array when the folder holds nothing):
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
  "content_hash": "9f2c…",
  "direction": "inbound",
  "stored_on_disk": true,
  "is_read": false,
  "is_flagged": false
}]
```

**Response details:** retrieval state, so an empty inbox can be judged trustworthy:
```json
{
  "folder": "INBOX",
  "count": 0,
  "limit": 50,
  "retrieval_enabled": true,
  "last_polled_at": "2026-07-29T17:48:00Z",
  "health_status": "ok"
}
```

`content_hash` is a SHA-256 over the content stored on disk (body parts and attachments). It is absent when the account's storage mode keeps no content.

**Folders.** MSNGR polls `INBOX` and lists locally stored messages. Requesting a folder that holds no stored messages returns `FOLDER_NOT_RETRIEVED` along with the folders that do, rather than an empty result — an empty folder, an unpolled one, and one that does not exist call for different responses.

Delivered outbound messages are recorded under the account's Sent folder, and `direction` distinguishes them from received mail. The folder's name comes from the server rather than being assumed — it is frequently `INBOX.Sent` rather than `Sent`, so read `available_folders` instead of guessing.

---

### msngr_poll_account

Retrieve new mail for the selected account immediately, instead of waiting for the next polling cycle.

**Auth:** Required | **Account:** Required | **Capability:** `read`

No parameters.

**Response data:**
```json
{
  "account_id": 1,
  "new_messages": 2,
  "last_polled_at": "2026-07-29T18:31:04Z",
  "health_status": "ok"
}
```

Rate-limited to one poll per account every 10 seconds; a call inside that window returns `POLL_TOO_SOON` with `retryable: true`. Retrieval is a round trip against someone else's mail server, so this is a request, not a guarantee of freshness.

Use it before concluding an inbox is empty: without it, an empty result cannot be distinguished from one the gateway has not looked for yet.

---

### msngr_read_message

Read a message including body text and HTML.

**Auth:** Required | **Account:** Required | **Capability:** `read`

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

**Auth:** Required | **Account:** Required | **Capability:** `read`

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
  { "ok": false, "error_code": "POLICY_DENIED", "matched_rule": "...", "suggestion": "...", "correlation_id": "..." }
  ```

All three outcomes return a `correlation_id`, including `deny`, so any outcome can be looked up later with `msngr_explain_decision`.

**`queued` is not `sent`.** It means policy passed and the gateway will attempt delivery. Transmission happens asynchronously in the outbound queue; call `msngr_queue_status` with the returned `queue_id` to find out whether it actually went.

**Pre-conditions:** Account must have `sending_enabled == true`. Agent must have `send` capability on the account.

---

### msngr_queue_status

Check the delivery state of a previously requested send.

**Auth:** Required | **Account:** Not required (scoped to accounts the agent has any permission on)

| Parameter | Type | Required | Description |
|---|---|---|---|
| `queue_id` | integer | yes | Queue ID returned by `msngr_request_send` |

**Response data:**
```json
{
  "queue_id": 10,
  "status": "sent",
  "means": "accepted by the SMTP server; see last_smtp_response for the server's reply",
  "account_id": 13,
  "correlation_id": "53a132f6-...",
  "from": "ash@sys.lu",
  "to": ["mike@sys.lu"],
  "cc": [],
  "subject": "Hello",
  "attempts": 1,
  "created_at": "2026-07-29T17:25:21Z",
  "updated_at": "2026-07-29T17:25:31Z",
  "sent_at": "2026-07-29T17:25:31Z",
  "last_attempt_at": "2026-07-29T17:25:31Z",
  "last_smtp_response": "250 2.0.0 Ok: queued as 4bLp2R"
}
```

`status` is one of `draft_requested`, `validation_failed`, `queued`, `held`, `rejected`, `sending`, `sent`, `failed`, `cancelled`. `means` spells out what that implies for the caller. `last_error` appears on failure; `hold_status` and `hold_reason` appear when the message was held.

A queue item belonging to an account the agent has no permission on returns `NOT_FOUND`, the same as one that does not exist.

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

**Auth:** Required | **Account:** Not required | **Capability:** `review_hold` on the held message's account

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
| `read` | `msngr_list_messages`, `msngr_read_message`, `msngr_search_messages`, `msngr_mark_message`, `msngr_delete_message`, `msngr_poll_account` |
| `send` | `msngr_request_send`, `msngr_validate_send` |
| `download_attachment` | `msngr_download_attachment` |
| `review_hold` | `msngr_review_hold` — not granted by default |
| *(any)* | `msngr_queue_status`, `msngr_list_holds` (scoped to accounts the agent has a permission on) |

Selecting an account proves only that the agent has *some* grant on it. Each verb checks its own capability, so an agent granted read-only cannot send, and one granted send-only cannot read the mailbox.

`review_hold` is deliberately excluded from the defaults granted at agent creation. A hold exists so a person decides; an agent that can release its own held mail has a delay, not a review. Even with the capability, an agent may never review a message it queued itself — that returns `SELF_REVIEW_FORBIDDEN`.

## Outbound Message Lifecycle

```
draft_requested -> queued -> sending -> sent
                         \-> held -> approved -> queued -> sending -> sent
                         \-> held -> rejected
                         \-> failed
                         \-> cancelled
```

All outbound mail passes through the queue processor. The queue runs on a configurable tick interval (`config.yaml` `ticks.queue_process_ms`, default 10 seconds).

## Audit Trail for a Send

Every send writes at least two audit events under one `correlation_id`, so a delivered message and a dropped one are distinguishable after the fact:

| Event | When | `outcome` |
|---|---|---|
| `send_requested` | Policy allowed the send and it entered the queue | `accepted` — the gateway agreed to try, nothing was transmitted |
| `message_held` | Policy held the send for review | `held` |
| `send_denied` | Policy denied the send | `denied` |
| `send_completed` | The SMTP server accepted the message | `success` |
| `send_failed` | The delivery attempt failed | `error` |

Request-time events record the recipients, subject and attachment count — the questions asked about a message that never arrived. Terminal events add `message_id`, `smtp_host`, `smtp_response` and `attempts`.

`outcome: "accepted"` on `send_requested` is deliberately not `"success"`: at that point nothing has been sent. Only `send_completed` reports transmission.

Retrieve the full trail for a message with `msngr_explain_decision` using the `correlation_id`.
