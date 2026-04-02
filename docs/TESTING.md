# MSNGR End-to-End Test Suite

## Prerequisites

- MSNGR running at `http://localhost:8600` (`make run`)
- Testmail server running at `http://localhost:7012/mcp`
- Master Admin operator account configured
- Two agents configured:
  - **Claude** (`claude@sys.lu`) — with a valid API token
  - **Test User** (`test@sys.lu`) — with a valid API token
- Two mail accounts: `claude@sys.lu` (ID 1), `test@sys.lu` (ID 2)
- Permissions:
  - Claude: send+read+list on account 1, read+list on account 2
  - Test User: send+read+list on account 2

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

### T1.3 — Verify Rules on Simulate Page
- Navigate to Rules > Simulate
- Test: agent "Claude", action "send", recipient "test@sys.lu", subject "Hello"
- Expected: **allow** (matches Rule 1 — internal domain)
- Test: agent "Claude", action "send", recipient "external@gmail.com", subject "Hello"
- Expected: **hold** (matches Rule 2 — external domain)
- Test: agent "Claude", action "send", recipient "test@sys.lu", subject "CONFIDENTIAL report"
- Expected: **deny** (matches Rule 3 — keyword block, priority 5 wins)

## Phase 2: Agent Claude — MCP Operations

All calls use Claude's Bearer token.

### T2.1 — List Accounts
- Call `msngr_list_accounts`
- Expected: returns 2 accounts (claude@sys.lu and test@sys.lu) — Claude has permissions on both

### T2.2 — Select Account
- Call `msngr_select_account` with `account_id: 1` (claude@sys.lu)
- Expected: success, account selected

### T2.3 — Send Internal Mail (should be ALLOWED)
- Call `msngr_request_send`:
  - to: `test@sys.lu`
  - subject: `E2E Test: Internal mail from Claude`
  - body_text: `This is an internal test message from Claude to Test User.`
- Expected: **queued** (policy allows internal sys.lu domain)
- Save the `correlation_id`

### T2.4 — Validate External Mail (should be HELD)
- Call `msngr_validate_send`:
  - to: `external@gmail.com`
  - subject: `E2E Test: External mail`
  - body_text: `This should be held.`
- Expected: outcome **hold** (matches Rule 2)

### T2.5 — Send Blocked Mail (should be DENIED)
- Call `msngr_request_send`:
  - to: `test@sys.lu`
  - subject: `CONFIDENTIAL project data`
  - body_text: `This message contains CONFIDENTIAL information.`
- Expected: **POLICY_DENIED** (matches Rule 3 — keyword block)

### T2.6 — Send External Mail (should be HELD)
- Call `msngr_request_send`:
  - to: `external@example.com`
  - subject: `E2E Test: Held message from Claude`
  - body_text: `This message should be held for operator review.`
- Expected: **held** for review (matches Rule 2 — external domain)

### T2.7 — Explain Decision
- Call `msngr_explain_decision` with the correlation_id from T2.3
- Expected: audit trail showing Layer A pass + Layer C allow (Rule 1)

### T2.8 — List Messages
- Call `msngr_list_messages` (folder: INBOX)
- Expected: success (may be empty if no inbound mail yet)

### T2.9 — Access Second Account (read-only)
- Call `msngr_select_account` with `account_id: 2` (test@sys.lu)
- Expected: success
- Call `msngr_list_messages`
- Expected: success (read access granted)

### T2.10 — Attempt Send on Read-Only Account (should be DENIED)
- With account 2 selected, call `msngr_request_send`:
  - to: `claude@sys.lu`
  - subject: `Unauthorized send`
  - body_text: `Claude should not be able to send from test@sys.lu`
- Expected: **deny** — Claude has no send permission on account 2, Layer A blocks it

## Phase 3: Agent Test User — MCP Operations

All calls use Test User's Bearer token.

### T3.1 — List Accounts
- Call `msngr_list_accounts`
- Expected: returns only 1 account (test@sys.lu) — Test User has no permissions on account 1

### T3.2 — Attempt to Select Unauthorized Account
- Call `msngr_select_account` with `account_id: 1` (claude@sys.lu)
- Expected: **ACCESS_DENIED**

### T3.3 — Select Own Account
- Call `msngr_select_account` with `account_id: 2` (test@sys.lu)
- Expected: success

### T3.4 — Reply to Claude (Internal, should be ALLOWED)
- Call `msngr_request_send`:
  - to: `claude@sys.lu`
  - subject: `E2E Test: Reply from Test User`
  - body_text: `Received your message. This is a reply from Test User.`
- Expected: **queued** (internal domain allowed)

### T3.5 — Search Messages
- Call `msngr_search_messages` with query: `E2E Test`
- Expected: success (returns any matching messages)

## Phase 4: Operator Review (Web UI via Playwright)

### T4.1 — Check Holds
- Navigate to Operations > Holds
- Verify held message from T2.6 appears with status "pending"

### T4.2 — Approve Hold
- Approve the held message
- Verify status changes to "approved"

### T4.3 — Check Queue
- Navigate to Operations > Queue
- Verify queued messages from T2.3 and T3.4 appear

### T4.4 — Check Audit Trail
- Navigate to Operations > Audit
- Verify audit events for: agent authentication, send requests, policy decisions, hold review

## Phase 5: Cross-Agent Mail Delivery Verification

### T5.1 — Send from Testmail to Claude's Account
- Use Testmail (`tm_send`) to send from `test01@sys.lu` to `claude@sys.lu`:
  - Subject: `E2E Test: Inbound to Claude`
  - Body: `This is an inbound message sent via Testmail.`
- Wait for IMAP polling (up to 30 seconds)

### T5.2 — Claude Reads Inbound Mail
- As Claude, select account 1, call `msngr_list_messages`
- Verify the inbound message from test01@sys.lu appears
- Call `msngr_read_message` with the message ID
- Verify subject and body match

### T5.3 — Claude Searches Messages
- Call `msngr_search_messages` with query: `Inbound to Claude`
- Verify the message is found

### T5.4 — Mark and Delete
- Call `msngr_mark_message` with flag: `read`
- Expected: success
- Call `msngr_delete_message` with the message ID
- Expected: policy evaluated (default deny applies since no delete-specific rule exists)

## Phase 6: Session Timeout Verification

### T6.1 — Verify Session Expiry
- This is a long-running test (skip in quick runs)
- Set MCP session timeout to 1 minute via Settings
- Authenticate as Claude, select account, list messages (success)
- Wait 70 seconds
- Attempt `msngr_list_messages` again
- Expected: **SESSION_EXPIRED** error

## Phase 7: HTML Email

### T7.1 — Send HTML Email via Testmail
- Use `tm_send` from `test02@sys.lu` to `test@sys.lu`
- Subject: `E2E HTML Email Test`
- Body: `<html><body><h1>Hello</h1><p>This is <b>HTML</b> with <a href='https://example.com'>a link</a>.</p></body></html>`
- Wait 35 seconds for IMAP polling

### T7.2 — Test User Reads HTML Email
- As Test User, select account 2, call `msngr_read_message`
- Verify HTML content is returned in body_text or body_html

## Phase 8: Queue Processor Delivery

### T8.1 — Claude Sends Internal Mail
- As Claude (account 1), send to `test03@sys.lu`
- Expected: queued, then delivered by queue processor

### T8.2 — Verify Delivery via Testmail
- Use `tm_check_inbox` for `test03@sys.lu`
- Verify the message arrived with correct content

## Phase 9: Hold Approval + Delivery

### T9.1 — Claude Sends External Mail (HELD)
- Send to `external@example.com`
- Expected: held

### T9.2 — Operator Approves + Queue Delivers
- Approve hold via web UI
- Wait for queue processor to deliver

---

## Known Gaps

- **Approve/reject audit logging**: Hold approval and rejection actions do not write audit events yet (send, deny, and hold events are logged)
- **Attachment testing**: Testmail sends plain text only; attachment round-trip not tested via IMAP
- **Session timeout test** (T6.1): Requires wait time, typically skipped in quick runs
