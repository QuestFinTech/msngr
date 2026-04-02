# Product & Architecture Specification

**Project:** MSNGR
**Expansion:** MCP Secure Mail Gateway Relay
**Status:** Product and architecture specification for first implementation

## 1. Purpose

MSNGR is a **policy-enforced mail gateway for MCP agents and human operators**. It provides controlled email sending and retrieval over IMAP and SMTP, with strong enforcement of who may perform which action, against which account, toward which recipients, under which rules.

MSNGR is **not** primarily a generic mail client. It is a **controlled mediation layer** between:
- agents using an MCP interface,
- operators using a built-in web UI,
- and external mail infrastructure accessed over IMAP/SMTP.

Its design priorities are:
- safety,
- least privilege,
- explainability,
- auditability,
- operational simplicity,
- and compact deployment.

## 2. Product statement

**MSNGR is a policy-enforced mail gateway for MCP agents and operators, providing controlled send/retrieve capabilities over IMAP/SMTP with auditability, explainable rule decisions, and least-privilege access.**

## 3. Goals

### 3.1 Primary goals
- Provide a stand-alone Go CLI program that can run as a foreground application or background service.
- Use a small YAML bootstrap configuration.
- Persist state and dynamic configuration in SQLite.
- Provide a built-in web UI for:
  - account setup,
  - rule configuration,
  - connectivity testing,
  - message hold/review workflows,
  - and diagnostics.
- Expose an MCP interface for agents to perform controlled mail actions.
- Support IMAP for retrieval and SMTP for sending.
- Enforce policy decisions before actions are executed.
- Return rich, structured error messages that agents can understand and react to.
- Support strong attribution and audit logging for all important actions.
- Allow deployers to define non-bypassable “hard” guardrails in Go.

### 3.2 Secondary goals
- Keep deployment simple.
- Keep the system understandable for operators.
- Avoid external infrastructure dependencies beyond mail servers.
- Preserve room for later evolution without overloading v0.1.

## 4. Non-goals for v0.1

The following are explicitly out of scope for the first version:
- Full-featured end-user mail client experience
- Groupware features such as calendars/contacts/tasks
- Multi-node clustering
- Advanced malware scanning
- S/MIME or PGP support
- Complex workflow automation beyond allow/deny/hold
- Real-time chat bridging such as IRC
- OAuth provider integrations unless specifically required by early target accounts
- Rich message composition editor in the web UI
- Full-text indexing/search of large mail stores

## 5. Design principles

1. **Policy first**  
   Every action must be evaluated against identity, capability, account scope, target scope, and content constraints.

2. **Least privilege**  
   Agents receive only the minimal permissions they need.

3. **Explainable decisions**  
   Every allow, deny, or hold outcome should be explainable in human and machine-usable terms.

4. **Safe by default**  
   Outbound messages should enter a lifecycle and be policy-checked before transmission.

5. **Operational simplicity**  
   Single binary, small config, SQLite state, easy observability.

6. **Auditability**  
   Important events must be attributable to a requesting actor and an effective decision.

7. **Separation of control layers**  
   Hard-coded safeguards, static config, dynamic policy, and runtime decision state should remain distinct.

## 6. High-level architecture

MSNGR v0.1 consists of the following major parts:

- **CLI/service process**
- **YAML bootstrap configuration**
- **SQLite database**
- **IMAP adapter**
- **SMTP adapter**
- **policy engine**
- **inbound processing loop**
- **outbound queue and sender loop**
- **operator web UI**
- **MCP server interface**
- **logging/audit subsystem**

### 6.1 Conceptual component diagram

```text
+--------------------+
|   MCP Agents       |
+---------+----------+
          |
          v
+--------------------+       +----------------------+
|   MCP Interface    |<----->|  Policy Engine       |
+---------+----------+       +-----------+----------+
          |                              |
          v                              v
+--------------------+       +----------------------+
|  Action Services   |<----->| SQLite State / Rules |
+---------+----------+       +----------------------+
          |
    +-----+---------------------------+
    |                                 |
    v                                 v
+-----------+                   +-------------+
| IMAP Loop  |                  | Outbound Q  |
+-----+------+                  +------+------+
      |                                |
      v                                v
+-----------+                   +-------------+
| IMAP srv  |                   | SMTP srv    |
+-----------+                   +-------------+

+--------------------+
| Operator Web UI    |
+--------------------+
```

## 7. Runtime model

MSNGR runs a main loop based on configurable ticks.

### 7.1 Tick configuration
The bootstrap config should support a configurable loop model such as:
- `ticks`: integer
- `tick_ms`: integer milliseconds

Practical implementation may internally normalize this into named intervals for:
- IMAP polling,
- outbound queue processing,
- maintenance jobs,
- and retention/cleanup.

### 7.2 Service behavior
MSNGR should be able to:
- run in the foreground as a CLI program,
- run as a service/daemon,
- expose a local web UI,
- expose MCP tools,
- and perform periodic work safely and predictably.

### 7.3 Recommended loop behavior
For v0.1, the loop should support:
- jitter to avoid rigid synchronized polling,
- backoff on repeated connection failures,
- graceful shutdown,
- bounded concurrency per account,
- and health/readiness reporting.

## 8. Trust and identity model

MSNGR must treat identity as first-class.

### 8.1 Actor classes
At minimum, the system recognizes:
- **system admin** — configures and operates MSNGR
- **human operator** — reviews holds, diagnostics, and message state
- **agent actor** — authenticated MCP caller with a named identity
- **mail account identity** — SMTP/IMAP account configured in MSNGR
- **external correspondent** — sender or recipient on the email side

### 8.2 Core authorization question
Every requested action should answer:

**Which agent may act via which mail account, toward which messages or recipients, using which verbs, under which content and policy constraints?**

### 8.3 Agent attribution
Every important action should preserve:
- requesting agent ID,
- request ID / correlation ID,
- effective account used,
- policy decision,
- and timestamps.

## 9. Configuration model

### 9.1 YAML bootstrap configuration
The YAML file should remain minimal and primarily define:
- server listen addresses
- database path
- encryption key reference or secret source reference
- initial admin/operator settings
- hard policy mode toggles
- logging mode
- retention defaults
- loop/tick settings

The YAML file should **not** be the main place for dynamic rule administration.

### 9.2 SQLite as state and dynamic config store
SQLite should store:
- configured mail accounts
- agent actor definitions
- dynamic rules
- message metadata
- optional stored message bodies
- attachment metadata
- outbound queue items
- hold/review items
- audit events
- health and delivery state
- migrations/schema version

## 10. Data handling modes

MSNGR should allow configurable data storage levels.

### 10.1 Recommended storage modes
- **metadata only**
- **metadata + headers**
- **metadata + body**
- **metadata + body + attachments**

This should be configurable globally and ideally overridable per account later.

### 10.2 Retention configuration
Retention should be configurable for:
- message metadata
- message body storage
- attachment storage
- audit events
- queue records
- connection/delivery logs
- keyword match events

## 11. Mail account model

Each account should define at least:
- unique account ID
- display name
- SMTP settings
- IMAP settings
- enabled/disabled state
- retrieval enabled/disabled
- sending enabled/disabled
- storage mode
- retention profile
- credential reference
- health state

### 11.1 Credential handling
Credentials should not be stored in plaintext when avoidable.

For v0.1:
- account metadata may live in SQLite
- account secrets should be encrypted at rest
- the encryption key must not be stored in the same SQLite database
- secrets must be redacted in UI, logs, and MCP responses

## 12. Capability model

Permissions should be explicit and action-scoped.

### 12.1 Inbound capabilities
- list messages
- read metadata
- read body
- search/filter
- download attachments
- mark read/unread
- move message
- delete message

### 12.2 Outbound capabilities
- create draft request
- validate send request
- queue send
- cancel queued send
- resend failed item
- reply
- forward

### 12.3 Administrative capabilities
- list accounts
- test connectivity
- inspect rules
- simulate decisions
- review holds
- approve or reject held items
- inspect audit trail

## 13. Policy engine

The policy engine is the core of MSNGR.

### 13.1 Decision outcomes
At minimum:
- **allow**
- **deny**
- **hold**

Optional later outcomes may include:
- modify/redact then allow
- quarantine
- require multi-step approval

### 13.2 Policy layers
MSNGR should separate policy into four layers:

#### Layer A — hard-coded guardrails in Go
These are compile-time or application-level controls that are intentionally difficult or impossible to bypass from the UI.

Examples:
- mandatory agent identity for MCP actions
- absolute deny lists for domains
- maximum message size
- forbidden attachment types
- no send unless an explicit agent-to-account mapping exists

#### Layer B — static YAML policy
Deployment-level defaults or constraints loaded at startup.

Examples:
- global send disable in maintenance mode
- global retention default
- default metadata-only mode

#### Layer C — dynamic DB/UI policy
Operational rules configurable in the application.

Examples:
- allowed domains
- allowed sender mappings
- keyword rules
- permitted actions per agent
- recipient restrictions

#### Layer D — runtime decision state
Short-lived or operational outcomes.

Examples:
- hold entries
- one-time approvals
- rate-limit counters
- temporary blocks
- retry state

### 13.3 Rule types for v0.1
Rules should support, at minimum:
- agent identity matching
- account matching
- sender address matching
- recipient address matching
- domain matching
- regex matching on mail addresses/domains
- action matching
- keyword presence matching
- keyword absence matching
- attachment presence matching
- attachment type matching
- size thresholds
- time-window checks
- recipient count limits

### 13.4 Rule outcomes
A rule may:
- allow
- deny
- hold
- annotate with explanation
- produce structured error details

### 13.5 Rule precedence
Rules must have:
- unique ID
- name
- enabled flag
- priority/order
- scope
- match criteria
- action
- explanation text
- created/updated metadata

The engine should record:
- all matched rules
- the final effective rule
- the final outcome
- a concise explanation

## 14. Hard rules and safety restrictions

MSNGR must support “hard” rules in Go for deployments that require strong guarantees.

### 14.1 Example hard rules
- limit sending to intra-domain addresses only
- allow sending only to a single explicit address
- allow only specified agents to send
- allow only specified agents to retrieve
- allow only specific actions per agent:
  - read
  - send
  - delete
  - mark
  - download attachments
- deny messages when certain keywords are present
- deny messages unless certain keywords are present

### 14.2 Additional recommended hard restrictions
- maximum number of recipients
- optional no-CC / no-BCC
- optional no-reply-all
- first-contact restrictions
- allowed hours/time windows
- maximum attachment size
- forbidden file extensions
- per-agent rate limits
- per-account rate limits

## 15. Outbound message lifecycle

Outbound send should not be modeled as direct execution only. It should go through an internal lifecycle.

### 15.1 Recommended states
- draft_requested
- validation_failed
- queued
- held
- rejected
- sending
- sent
- failed
- cancelled

### 15.2 Send flow
1. Agent requests send
2. Request is validated for schema and permissions
3. Policy engine evaluates request
4. Outcome is allow / deny / hold
5. Allowed items enter outbound queue
6. Sender loop processes queue
7. Delivery result is recorded
8. Audit/event records are persisted

### 15.3 Why queueing matters
Queueing provides:
- retry support
- auditability
- operational visibility
- better error reporting
- hold/review workflows
- safer behavior under transient SMTP failures

## 16. Inbound processing lifecycle

Inbound retrieval should also be modeled explicitly.

### 16.1 Retrieval flow
1. IMAP account selected for polling
2. Connection established
3. New or changed messages discovered
4. Deduplication check performed
5. Metadata retrieved
6. Optional body retrieval based on policy/storage mode
7. Inbound rules applied
8. Data persisted
9. Message exposed to operator/UI/MCP tools
10. Optional server-side mark/move/delete actions executed if allowed

### 16.2 Deduplication and idempotency
MSNGR should use a combination of:
- message ID
- IMAP UID / UIDVALIDITY
- internal content hashes where useful
- action/request correlation IDs

to reduce duplicates and safe-retry problems.

## 17. Attachment handling

Attachments should be handled as a separate policy surface.

### 17.1 v0.1 requirements
- metadata capture for attachments
- configurable attachment download permissions
- MIME/type and extension checks
- maximum attachment size checks
- optional attachment storage
- attachment hash recording if stored
- clear logging and audit of attachment access

### 17.2 Recommended deny-by-default stance
For many deployments, attachment download should default to off unless explicitly granted.

## 18. Logging and observability

### 18.1 Log classes
MSNGR should conceptually separate:
- **audit log** — who requested what and what was decided
- **operational log** — network/connectivity/runtime behavior
- **message event log** — message lifecycle transitions

### 18.2 Audit event examples
- agent requested outbound send
- outbound item held by rule
- operator approved held message
- message deleted by agent
- attachment downloaded by agent
- account credentials test failed

### 18.3 Metrics and health
Even if advanced metrics are postponed, v0.1 should be structured to support:
- queue depth
- per-account health
- poll success/failure counters
- send success/failure counters
- rule hit counters
- average SMTP/IMAP latency

## 19. Web UI

The built-in web UI is for operators, not for full end-user mail usage.

### 19.1 v0.1 UI responsibilities
- bootstrap/setup assistance
- mail account configuration
- connectivity testing
- rule definition and editing
- rule ordering/priorities
- view message queue
- review held items
- inspect decisions and matched rules
- retention configuration
- inspect audit history
- basic system diagnostics

### 19.2 UI design priorities
- minimal and clear
- operator-oriented
- easy error interpretation
- easy rule simulation
- strong redaction of sensitive values

## 20. MCP interface

MSNGR should expose a focused set of MCP tools rather than one large catch-all mail tool.

### 20.1 Suggested MCP tools for v0.1
- `msngr_list_messages`
- `msngr_read_message`
- `msngr_search_messages`
- `msngr_request_send`
- `msngr_validate_send`
- `msngr_mark_message`
- `msngr_delete_message`
- `msngr_download_attachment`
- `msngr_list_holds`
- `msngr_review_hold`
- `msngr_explain_decision`
- `msngr_list_accounts`
- `msngr_test_account_connectivity`

### 20.2 MCP tool design guidelines
Each tool should:
- be narrowly scoped
- declare required permissions
- return structured, explainable outcomes
- include usage documentation
- preserve attribution metadata

### 20.3 Example MCP response model
```json
{
  "ok": false,
  "error_code": "RECIPIENT_FORBIDDEN",
  "message": "Send denied: recipient domain is not allowed for this agent.",
  "details": {
    "agent": "agent.researcher",
    "account": "ops@example.com",
    "recipient": "user@gmail.com",
    "matched_rule": "allow_internal_only",
    "retryable": false,
    "suggestion": "Use an approved internal address or request operator approval."
  }
}
```

## 21. Error model

Rich error responses are essential for agent usability.

### 21.1 Error response fields
Recommended fields:
- `ok`
- `error_code`
- `message`
- `details`
- `retryable`
- `matched_rule`
- `suggestion`
- `correlation_id`

### 21.2 Example error categories
- authentication failed
- account unavailable
- policy denied
- policy hold required
- message not found
- attachment forbidden
- keyword policy triggered
- invalid recipient
- too many recipients
- rate limit exceeded
- retryable transport failure
- permanent transport failure

## 22. Security requirements

### 22.1 Authentication and authorization
- MCP callers must map to named agent identities
- agent permissions must be explicit
- operator access to web UI must be protected
- admin/operator distinction should exist even if initially simple

### 22.2 Secret hygiene
- no plaintext secrets in logs
- redact secrets in all outputs
- encrypt secrets at rest
- keep key material separate from DB

### 22.3 Content protection
- configurable storage mode
- configurable retention
- optional metadata-only mode
- explicit attachment policy

### 22.4 Safe defaults
- no agent access without explicit identity
- no send without account mapping
- deny or hold on ambiguity
- queue outbound instead of direct fire-and-forget

## 23. Suggested SQLite entities

The exact schema is implementation detail, but the following tables/entities are likely useful:

- `accounts`
- `account_credentials`
- `agents`
- `agent_permissions`
- `rules`
- `rule_matches`
- `messages`
- `message_headers`
- `message_bodies`
- `attachments`
- `outbound_queue`
- `holds`
- `audit_events`
- `delivery_attempts`
- `keyword_events`
- `system_settings`
- `migrations`

## 24. Suggested CLI surface

Example command structure:

```text
msngr run
msngr init
msngr migrate
msngr doctor
msngr config check
msngr account test
msngr rule simulate
msngr export audit
```

### 24.1 Useful v0.1 CLI commands
- `run` — start service
- `init` — initialize DB/bootstrap state
- `migrate` — apply schema migrations
- `doctor` — system diagnostics
- `config check` — validate bootstrap YAML
- `account test` — test SMTP/IMAP connectivity
- `rule simulate` — evaluate a hypothetical action against policies

## 25. Operational requirements

### 25.1 Reliability
- bounded worker pools
- exponential backoff on repeated failures
- graceful shutdown
- queue persistence
- WAL mode recommended for SQLite
- schema migrations required

### 25.2 Health/readiness
A local health endpoint or status surface should report:
- DB availability
- web UI/MCP listener state
- queue size
- number of unhealthy accounts
- last successful IMAP poll
- last successful SMTP send

