# MSNGR End-to-End Test Suite

## Prerequisites

- MSNGR running at `http://localhost:8600` (`make run`)
- Playwright MCP server running (for web UI tests)
- Master Admin operator account configured
- Two agents configured:
  - **Claude** (`claude@sys.lu`) — with a valid API token
  - **Test User** (`test@sys.lu`) — with a valid API token
- Two mail accounts: `claude@sys.lu` (ID 1), `test@sys.lu` (ID 2)
- Permissions:
  - Claude: send+read+list on account 1, read+list+download_attachment on account 2
  - Test User: send+read+list on account 2

No external mail services are required — all tests use MSNGR's own MCP tools to send mail between accounts, with IMAP polling to verify delivery.

## Phase 1: Operator Setup (Web UI via Playwright)

### T1.1 — Login as Master Admin
- Navigate to `http://localhost:8600/login`
- Login with operator credentials
- Verify redirect to `/dashboard`

### T1.2 — Create Policy Rules
Create the following rules via the Rules > Manage page:

**Rule 1: Allow internal mail** (priority 10)
- Action: allow
- Match: `{"domain": "sys.lu", "action_type": "send"}`
- Explanation: "Allow sending to internal sys.lu domain"

**Rule 2: Hold external mail** (priority 20)
- Action: hold
- Match: `{"action_type": "send"}`
- Explanation: "Hold all outbound mail to external domains for review"

**Rule 3: Deny keyword "CONFIDENTIAL"** (priority 5)
- Action: deny
- Match: `{"keywords_present": ["CONFIDENTIAL"], "action_type": "send"}`
- Explanation: "Block messages containing CONFIDENTIAL"

**Rule 4: Allow delete for internal messages** (priority 15)
- Action: allow
- Match: `{"domain": "sys.lu", "action_type": "delete"}`
- Explanation: "Allow deleting messages from internal sys.lu domain"

### T1.3 — Verify Rules on Simulate Page
- Navigate to Rules > Simulate
- Test: agent "Claude", account "claude@sys.lu", action "send", recipient "test@sys.lu", subject "Hello"
- Expected: **allow** (matches Rule 1 — internal domain)
- Test: agent "Claude", account "claude@sys.lu", action "send", recipient "external@gmail.com", subject "Hello"
- Expected: **hold** (matches Rule 2 — external domain)
- Test: agent "Claude", account "claude@sys.lu", action "send", recipient "test@sys.lu", subject "CONFIDENTIAL report"
- Expected: **deny** (matches Rule 3 — keyword block, priority 5 wins)

## Phase 2: Agent Authentication (MCP Login)

### T2.1 — Login as Claude
- Call `msngr_login` with `login_email: "claude@sys.lu"` and Claude's API token
- Expected: success, response includes `agent_id`, `display_name: "Claude"`, `agent_email: "claude@sys.lu"`

### T2.2 — Login with Invalid Token
- Call `msngr_login` with `login_email: "claude@sys.lu"` and an invalid token (e.g. `"0000000000000000000000000000000000000000000000000000000000000000"`)
- Expected: **invalid credentials** (generic error, no detail leak)

### T2.3 — Login with Mismatched Email
- Call `msngr_login` with `login_email: "wrong@sys.lu"` and Claude's valid token
- Expected: **invalid credentials** (token exists but email doesn't match)

### T2.4 — Login as Test User
- Call `msngr_login` with `login_email: "test@sys.lu"` and Test User's API token
- Expected: success, response includes `display_name: "Test User"`, `agent_email: "test@sys.lu"`

## Phase 3: Agent Claude — MCP Operations

Authenticate as Claude via `msngr_login` before running these tests.

### T3.1 — List Accounts
- Call `msngr_list_accounts`
- Expected: returns 2 accounts (claude@sys.lu and test@sys.lu) — Claude has permissions on both

### T3.2 — Select Account
- Call `msngr_select_account` with `account_id: 1` (claude@sys.lu)
- Expected: success, account selected

### T3.3 — Test Account Connectivity
- Call `msngr_test_account_connectivity` with `account_id: 1`
- Expected: success with IMAP and SMTP status for claude@sys.lu (both `ok: true` if mail server is reachable)

### T3.4 — Test Connectivity on Unauthorized Account
- Call `msngr_test_account_connectivity` with a non-existent or unauthorized `account_id`
- Expected: **ACCESS_DENIED** or **NOT_FOUND**

### T3.5 — Send Internal Mail (should be ALLOWED)
- Call `msngr_request_send`:
  - to: `test@sys.lu`
  - subject: `E2E Test: Internal mail from Claude`
  - body_text: `This is an internal test message from Claude to Test User.`
- Expected: **queued** (policy allows internal sys.lu domain)
- Save the `correlation_id`

### T3.6 — Validate External Mail (should be HELD)
- Call `msngr_validate_send`:
  - to: `external@gmail.com`
  - subject: `E2E Test: External mail`
  - body_text: `This should be held.`
- Expected: outcome **hold** (matches Rule 2)

### T3.7 — Send Blocked Mail (should be DENIED)
- Call `msngr_request_send`:
  - to: `test@sys.lu`
  - subject: `CONFIDENTIAL project data`
  - body_text: `This message contains CONFIDENTIAL information.`
- Expected: **POLICY_DENIED** (matches Rule 3 — keyword block)

### T3.8 — Send External Mail (should be HELD)
- Call `msngr_request_send`:
  - to: `external@example.com`
  - subject: `E2E Test: Held message from Claude`
  - body_text: `This message should be held for operator review.`
- Expected: **held** for review (matches Rule 2 — external domain)

### T3.9 — Explain Decision
- Call `msngr_explain_decision` with the correlation_id from T3.5
- Expected: audit trail showing Layer A pass + Layer C allow (Rule 1)

### T3.10 — List Messages
- Call `msngr_list_messages` (folder: INBOX)
- Expected: success (may be empty if no inbound mail yet)

### T3.11 — Access Second Account (read-only)
- Call `msngr_select_account` with `account_id: 2` (test@sys.lu)
- Expected: success
- Call `msngr_list_messages`
- Expected: success (read access granted)

### T3.12 — Attempt Send on Read-Only Account (should be DENIED)
- With account 2 selected, call `msngr_request_send`:
  - to: `claude@sys.lu`
  - subject: `Unauthorized send`
  - body_text: `Claude should not be able to send from test@sys.lu`
- Expected: **deny** — Claude has no send permission on account 2

## Phase 4: Agent Test User — MCP Operations

Authenticate as Test User via `msngr_login` before running these tests.

### T4.1 — List Accounts
- Call `msngr_list_accounts`
- Expected: returns only 1 account (test@sys.lu) — Test User has no permissions on account 1

### T4.2 — Attempt to Select Unauthorized Account
- Call `msngr_select_account` with `account_id: 1` (claude@sys.lu)
- Expected: **ACCESS_DENIED**

### T4.3 — Select Own Account
- Call `msngr_select_account` with `account_id: 2` (test@sys.lu)
- Expected: success

### T4.4 — Reply to Claude (Internal, should be ALLOWED)
- Call `msngr_request_send`:
  - to: `claude@sys.lu`
  - subject: `E2E Test: Reply from Test User`
  - body_text: `Received your message. This is a reply from Test User.`
- Expected: **queued** (internal domain allowed)

### T4.5 — Search Messages
- Call `msngr_search_messages` with query: `E2E Test`
- Expected: success (returns any matching messages)

## Phase 5: Operator Review (Web UI via Playwright)

### T5.1 — Check Holds
- Navigate to Operations > Holds
- Verify held message from T3.8 appears with status "pending"

### T5.2 — Approve Hold
- Approve the held message
- Verify status changes to "released"

### T5.3 — Check Queue
- Navigate to Operations > Queue
- Verify queued messages from T3.5 and T4.4 appear

### T5.4 — Check Audit Trail
- Navigate to Operations > Audit
- Verify audit events for: agent login, send requests, policy decisions, hold review

## Phase 6: Cross-Agent Mail Delivery Verification

### T6.1 — Test User Sends to Claude
- As Test User (account 2), call `msngr_request_send`:
  - to: `claude@sys.lu`
  - subject: `E2E Test: Inbound to Claude`
  - body_text: `This is a cross-agent message from Test User to Claude.`
- Expected: **queued** (internal domain allowed)
- Wait for queue delivery + IMAP polling (up to 45 seconds, retry `msngr_list_messages`)

### T6.2 — Claude Reads Inbound Mail
- As Claude, select account 1, call `msngr_list_messages`
- Verify the inbound message from test@sys.lu appears
- Call `msngr_read_message` with the message ID
- Verify subject and body match

### T6.3 — Claude Searches Messages
- Call `msngr_search_messages` with query: `Inbound to Claude`
- Verify the message is found

### T6.4 — Mark and Delete
- Call `msngr_mark_message` with flag: `read`
- Expected: success
- Call `msngr_delete_message` with the message ID
- Expected: policy evaluated — **allow** (Rule 4 matches: internal domain + delete action)

## Phase 7: Session Timeout Verification

### T7.1 — Verify Session Expiry
- This is a long-running test (skip in quick runs)
- Set MCP session timeout to 1 minute via Settings
- Call `msngr_login` as Claude, select account, list messages (success)
- Wait 70 seconds
- Attempt `msngr_list_messages` again
- Expected: **SESSION_EXPIRED** error

## Phase 8: HTML Email via MCP

### T8.1 — Send HTML Email
- As Claude (account 1), call `msngr_request_send`:
  - to: `test@sys.lu`
  - subject: `E2E HTML Email Test`
  - body_text: `This is the plain text version.`
  - body_html: `<html><body><h1>Hello</h1><p>This is <b>HTML</b> with <a href='https://example.com'>a link</a>.</p></body></html>`
- Expected: **queued**
- Wait for queue delivery + IMAP polling (up to 45 seconds)

### T8.2 — Test User Reads HTML Email
- As Test User, select account 2, call `msngr_list_messages`
- Find the HTML email, call `msngr_read_message`
- Verify HTML content is returned in body_html (or body_text contains HTML tags)

## Phase 9: Attachment Round-Trip

### T9.1 — Send Email with Attachments
- As Claude (account 1), call `msngr_request_send`:
  - to: `test@sys.lu`
  - subject: `E2E Test: Attachment round-trip`
  - body_text: `This message has a text file and a binary image attached.`
  - attachments:
    ```json
    [
      {"filename": "hello.txt", "mime_type": "text/plain", "content_base64": "<base64 of text content>"},
      {"filename": "pixel.png", "mime_type": "image/png", "content_base64": "<base64 of a small PNG>"}
    ]
    ```
- Expected: **queued** (internal domain allowed)
- Wait for queue delivery + IMAP polling (up to 45 seconds)

### T9.2 — Download Attachment (Authorized)
- As Claude, select account 2 (has `download_attachment` permission)
- Call `msngr_search_messages` to find the attachment message
- Call `msngr_download_attachment` with `message_id` and `filename: "hello.txt"`
- Expected: success with base64-encoded data, filename, and size
- Decode the base64 and verify content matches the original text
- Call `msngr_download_attachment` with `filename: "pixel.png"`
- Expected: success — decode base64 and verify it's a valid PNG image

### T9.3 — Download Attachment Without Permission
- As Test User (no `download_attachment` capability on account 2), attempt `msngr_download_attachment`
- Expected: **ACCESS_DENIED** — agent lacks `download_attachment` capability

## Phase 10: Queue Processor Delivery Verification

### T10.1 — Claude Sends Internal Mail
- As Claude (account 1), send to `test@sys.lu`:
  - subject: `E2E Test: Queue delivery verification`
  - body_text: `This message verifies end-to-end queue delivery.`
- Expected: queued, then delivered by queue processor

### T10.2 — Verify Delivery
- As Test User, select account 2, call `msngr_list_messages`
- Verify the message arrived with correct subject and body via `msngr_read_message`

## Phase 11: Hold Approval + Delivery

### T11.1 — Claude Sends External Mail (HELD)
- As Claude (account 1), send to `external@example.com`
- Expected: held

### T11.2 — Operator Approves + Queue Delivers
- Approve hold via web UI (Operations > Holds > Release)
- Wait for queue processor to deliver
- Verify queue status changes to "sent" or "sending" (Operations > Queue)

## Phase 12: Bearer Token Fallback

### T12.1 — Authenticate via Bearer Header
- Configure MCP client with `Authorization: Bearer <token>` header (no `msngr_login` call)
- Call `msngr_list_accounts`
- Expected: success — Bearer token auth still works as fallback

---

## Known Gaps

- **Approve/reject audit logging**: Hold approval and rejection actions do not write audit events yet (send, deny, and hold events are logged)
- **Session timeout test** (T7.1): Requires wait time, typically skipped in quick runs
- **Idempotency**: No teardown between runs — rules from T1.2 will accumulate on repeated runs. Consider adding a cleanup step or checking for existing rules before creation.
