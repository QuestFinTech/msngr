// Package model defines the domain types used throughout MSNGR, including
// operators, mail accounts, agents, policy rules, messages, and audit events.
package model

import "time"

// Operator represents a web UI user (admin or operator).
type Operator struct {
	ID           int64   `json:"id"`
	Name         string  `json:"name"`
	Email        string  `json:"email"`
	PasswordHash string  `json:"-"`
	Role         string  `json:"role"` // master_admin, admin, operator
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
	LastLoginAt  *string `json:"last_login_at,omitempty"`
}

// MailServer represents a shared mail server configuration (IMAP/SMTP).
type MailServer struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	IMAPHost  string `json:"imap_host"`
	IMAPPort  int    `json:"imap_port"`
	IMAPTLS   bool   `json:"imap_tls"`
	SMTPHost  string `json:"smtp_host"`
	SMTPPort  int    `json:"smtp_port"`
	SMTPTLS   bool   `json:"smtp_tls"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Account represents a configured mail account (IMAP/SMTP).
type Account struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	EmailAddress      string `json:"email_address"`
	ServerID          int64  `json:"server_id"`
	ServerName        string `json:"server_name,omitempty"`
	SMTPHost          string `json:"smtp_host"`
	SMTPPort          int    `json:"smtp_port"`
	SMTPTLS           bool   `json:"smtp_tls"`
	IMAPHost          string `json:"imap_host"`
	IMAPPort          int    `json:"imap_port"`
	IMAPTLS           bool   `json:"imap_tls"`
	RetrievalEnabled      bool   `json:"retrieval_enabled"`
	SendingEnabled        bool   `json:"sending_enabled"`
	DeleteAfterRetrieval  bool   `json:"delete_after_retrieval"`
	StorageMode           string `json:"storage_mode"` // metadata, headers, body, full
	Enabled           bool   `json:"enabled"`
	HealthStatus      string `json:"health_status"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// Agent represents an MCP caller with a named identity.
type Agent struct {
	ID          int64  `json:"id"`
	AgentEmail  string `json:"agent_email"`
	DisplayName string `json:"display_name"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// AgentPermission maps an agent to a capability on an account.
type AgentPermission struct {
	ID         int64  `json:"id"`
	AgentID    int64  `json:"agent_id"`
	AccountID  int64  `json:"account_id"`
	Capability string `json:"capability"`
}

// Rule represents a policy rule (Layer B/C/D).
type Rule struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Priority      int    `json:"priority"`
	Layer         string `json:"layer"`  // B, C, D
	Scope         string `json:"scope"`  // global, account, agent
	MatchCriteria string `json:"match_criteria"` // JSON
	Action        string `json:"action"` // allow, deny, hold
	Explanation   string `json:"explanation"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// Message represents an email message (inbound or outbound metadata).
type Message struct {
	ID              int64   `json:"id"`
	AccountID       int64   `json:"account_id"`
	MessageID       string  `json:"message_id"` // RFC Message-ID
	IMAPUID         int64   `json:"imap_uid"`
	IMAPUIDValidity int64   `json:"imap_uidvalidity"`
	Folder          string  `json:"folder"`
	FromAddr        string  `json:"from_addr"`
	ToAddrs         string  `json:"to_addrs"`  // JSON array
	CcAddrs         string  `json:"cc_addrs"`  // JSON array
	Subject         string  `json:"subject"`
	Date            string  `json:"date"`
	Size            int64   `json:"size"`
	ContentHash     string  `json:"content_hash"`
	Direction       string  `json:"direction"` // inbound, outbound
	RetrievedAt     string  `json:"retrieved_at"`
	ArchivePath     string  `json:"archive_path,omitempty"`
	StoredOnDisk    bool    `json:"stored_on_disk"`
	IsRead          bool    `json:"is_read"`
	IsFlagged       bool    `json:"is_flagged"`
}

// OutboundItem represents a queued outbound message.
type OutboundItem struct {
	ID            int64   `json:"id"`
	AccountID     int64   `json:"account_id"`
	AgentID       *int64  `json:"agent_id,omitempty"`
	CorrelationID string  `json:"correlation_id"`
	Status        string  `json:"status"` // draft_requested, queued, held, rejected, sending, sent, failed, cancelled
	FromAddr      string  `json:"from_addr"`
	ToAddrs       string  `json:"to_addrs"` // JSON array
	CcAddrs       string  `json:"cc_addrs"`
	Subject       string  `json:"subject"`
	BodyText      string  `json:"body_text"`
	BodyHTML         string  `json:"body_html"`
	AttachmentsJSON  string  `json:"attachments_json,omitempty"` // JSON array of Attachment objects
	CreatedAt        string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	SentAt        *string `json:"sent_at,omitempty"`
	ErrorMessage  string  `json:"error_message,omitempty"`
}

// Attachment represents a file attached to an outbound message.
type Attachment struct {
	Filename      string `json:"filename"`
	MimeType      string `json:"mime_type"`
	ContentBase64 string `json:"content_base64"`
}

// Hold represents a held outbound item pending review.
type Hold struct {
	ID         int64   `json:"id"`
	QueueID    int64   `json:"queue_id"`
	RuleID     int64   `json:"rule_id"`
	Reason     string  `json:"reason"`
	Status     string  `json:"status"` // pending, approved, rejected
	ReviewerID *int64  `json:"reviewer_id,omitempty"`
	ReviewedAt *string `json:"reviewed_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

// AgentToken represents an API token authenticating an agent.
type AgentToken struct {
	ID         int64   `json:"id"`
	TokenHash  string  `json:"-"`
	AgentID    int64   `json:"agent_id"`
	Enabled    bool    `json:"enabled"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	// Joined fields (for display / auth context)
	AgentName  string `json:"agent_name,omitempty"`
	AgentEmail string `json:"agent_email,omitempty"`
}

// MCPSession holds the state for an authenticated MCP agent session.
type MCPSession struct {
	Agent                *Agent
	Token                *AgentToken
	SelectedAccountID    int64
	SelectedAccountEmail string
	AuthenticatedAt      time.Time
}

// AuditEvent represents an auditable action.
type AuditEvent struct {
	ID            int64  `json:"id"`
	ActorType     string `json:"actor_type"` // system, operator, agent
	ActorID       string `json:"actor_id"`
	Action        string `json:"action"`
	TargetType    string `json:"target_type,omitempty"`
	TargetID      string `json:"target_id,omitempty"`
	Outcome       string `json:"outcome"` // success, denied, error
	DetailsJSON   string `json:"details_json,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	CreatedAt     string `json:"created_at"`
}
