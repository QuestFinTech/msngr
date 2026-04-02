// Package db provides SQLite database access for all MSNGR domain objects,
// including operators, accounts, agents, rules, messages, and audit events.
package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/luxemque/msngr/internal/model"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a SQLite database connection.
type DB struct {
	conn *sql.DB
}

// Open creates a new database connection and configures SQLite pragmas.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure SQLite for reliability and performance.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("exec %s: %w", p, err)
		}
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// nowUTC returns the current time in UTC formatted as RFC3339.
func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// scanner is an interface satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// scanAccount scans a row from the 18-column account query (with server JOIN).
func scanAccount(s scanner) (model.Account, error) {
	var a model.Account
	err := s.Scan(
		&a.ID, &a.Name, &a.EmailAddress,
		&a.ServerID, &a.ServerName,
		&a.SMTPHost, &a.SMTPPort, &a.SMTPTLS,
		&a.IMAPHost, &a.IMAPPort, &a.IMAPTLS,
		&a.RetrievalEnabled, &a.SendingEnabled, &a.StorageMode,
		&a.Enabled, &a.HealthStatus, &a.CreatedAt, &a.UpdatedAt,
	)
	return a, err
}

// scanMessage scans a row from the 19-column message query.
func scanMessage(s scanner) (model.Message, error) {
	var m model.Message
	err := s.Scan(
		&m.ID, &m.AccountID, &m.MessageID, &m.IMAPUID, &m.IMAPUIDValidity,
		&m.Folder, &m.FromAddr, &m.ToAddrs, &m.CcAddrs,
		&m.Subject, &m.Date, &m.Size, &m.ContentHash,
		&m.Direction, &m.RetrievedAt, &m.ArchivePath, &m.StoredOnDisk,
		&m.IsRead, &m.IsFlagged,
	)
	return m, err
}

// scanAuditEvent scans a row from the 10-column audit event query.
func scanAuditEvent(s scanner) (model.AuditEvent, error) {
	var e model.AuditEvent
	err := s.Scan(&e.ID, &e.ActorType, &e.ActorID, &e.Action, &e.TargetType, &e.TargetID, &e.Outcome, &e.DetailsJSON, &e.CorrelationID, &e.CreatedAt)
	return e, err
}

// scanRule scans a row from the 11-column rule query.
func scanRule(s scanner) (model.Rule, error) {
	var r model.Rule
	err := s.Scan(&r.ID, &r.Name, &r.Enabled, &r.Priority, &r.Layer, &r.Scope, &r.MatchCriteria, &r.Action, &r.Explanation, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// InitSchema applies the database schema. It is idempotent and safe to call
// on every startup since all statements use CREATE TABLE IF NOT EXISTS.
func (db *DB) InitSchema() error {
	data, err := migrationsFS.ReadFile("migrations/001_schema.sql")
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	if _, err := db.conn.Exec(string(data)); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	slog.Info("Database schema applied")
	return nil
}

// --- Operator queries ---

// CountOperators returns the number of operators in the database.
func (db *DB) CountOperators() (int, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM operators").Scan(&count)
	return count, err
}

// CreateOperator inserts a new operator and returns its ID.
func (db *DB) CreateOperator(name, email, passwordHash, role string) (int64, error) {
	now := nowUTC()
	res, err := db.conn.Exec(
		"INSERT INTO operators (name, email, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		name, email, passwordHash, role, now, now,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetOperatorByEmail returns an operator by email address.
func (db *DB) GetOperatorByEmail(email string) (*model.Operator, error) {
	op := &model.Operator{}
	err := db.conn.QueryRow(
		"SELECT id, name, email, password_hash, role, created_at, updated_at, last_login_at FROM operators WHERE email = ?",
		email,
	).Scan(&op.ID, &op.Name, &op.Email, &op.PasswordHash, &op.Role, &op.CreatedAt, &op.UpdatedAt, &op.LastLoginAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return op, nil
}

// GetOperatorByID returns an operator by ID.
func (db *DB) GetOperatorByID(id int64) (*model.Operator, error) {
	op := &model.Operator{}
	err := db.conn.QueryRow(
		"SELECT id, name, email, password_hash, role, created_at, updated_at, last_login_at FROM operators WHERE id = ?",
		id,
	).Scan(&op.ID, &op.Name, &op.Email, &op.PasswordHash, &op.Role, &op.CreatedAt, &op.UpdatedAt, &op.LastLoginAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return op, nil
}

// UpdateOperatorLogin updates the last_login_at timestamp.
func (db *DB) UpdateOperatorLogin(id int64) error {
	now := nowUTC()
	_, err := db.conn.Exec("UPDATE operators SET last_login_at = ? WHERE id = ?", now, id)
	return err
}

// SetSystemSetting upserts a system setting.
func (db *DB) SetSystemSetting(key, value string) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		"INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
		key, value, now,
	)
	return err
}

// GetSystemSetting retrieves a system setting value.
func (db *DB) GetSystemSetting(key string) (string, error) {
	var value string
	err := db.conn.QueryRow("SELECT value FROM system_settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// --- Stats queries (for dashboard) ---

// DashboardStats holds counts for the dashboard.
type DashboardStats struct {
	Accounts    int
	Agents      int
	QueueDepth  int
	PendingHolds int
	AuditEvents int
	Rules       int
}

// GetDashboardStats returns aggregate counts for the dashboard.
func (db *DB) GetDashboardStats() (*DashboardStats, error) {
	s := &DashboardStats{}
	queries := []struct {
		query string
		dest  *int
	}{
		{"SELECT COUNT(*) FROM accounts", &s.Accounts},
		{"SELECT COUNT(*) FROM agents", &s.Agents},
		{"SELECT COUNT(*) FROM outbound_queue WHERE status IN ('queued','sending')", &s.QueueDepth},
		{"SELECT COUNT(*) FROM holds WHERE status = 'pending'", &s.PendingHolds},
		{"SELECT COUNT(*) FROM audit_events", &s.AuditEvents},
		{"SELECT COUNT(*) FROM rules WHERE enabled = 1", &s.Rules},
	}
	for _, q := range queries {
		if err := db.conn.QueryRow(q.query).Scan(q.dest); err != nil {
			return nil, fmt.Errorf("stats query %s: %w", q.query, err)
		}
	}
	return s, nil
}

// --- Policy engine queries ---

// GetEnabledRules returns all enabled rules ordered by priority (ascending).
func (db *DB) GetEnabledRules(ctx context.Context) ([]model.Rule, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT id, name, enabled, priority, layer, scope, match_criteria, action, COALESCE(explanation, ''), created_at, updated_at
		 FROM rules
		 WHERE enabled = 1
		 ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query enabled rules: %w", err)
	}
	defer rows.Close()

	var rules []model.Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// CheckAgentAccountMapping returns true if the given agent (by numeric ID)
// has at least one permission entry for the specified account.
func (db *DB) CheckAgentAccountMapping(ctx context.Context, agentID int64, accountID int64) (bool, error) {
	var count int
	err := db.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_permissions ap
		 JOIN agents a ON a.id = ap.agent_id
		 WHERE ap.agent_id = ? AND ap.account_id = ? AND a.enabled = 1`,
		agentID, accountID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check agent-account mapping: %w", err)
	}
	return count > 0, nil
}

// --- Outbound queue queries ---

// GetQueuedItems returns up to `limit` items with status 'queued', oldest first.
func (db *DB) GetQueuedItems(limit int) ([]model.OutboundItem, error) {
	rows, err := db.conn.Query(
		"SELECT id, account_id, agent_id, correlation_id, status, from_addr, to_addrs, COALESCE(cc_addrs, ''), subject, COALESCE(body_text, ''), COALESCE(body_html, ''), created_at, updated_at, sent_at, COALESCE(error_message, '') FROM outbound_queue WHERE status = 'queued' ORDER BY created_at ASC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query queued items: %w", err)
	}
	defer rows.Close()

	var items []model.OutboundItem
	for rows.Next() {
		var item model.OutboundItem
		if err := rows.Scan(
			&item.ID, &item.AccountID, &item.AgentID, &item.CorrelationID,
			&item.Status, &item.FromAddr, &item.ToAddrs, &item.CcAddrs,
			&item.Subject, &item.BodyText, &item.BodyHTML,
			&item.CreatedAt, &item.UpdatedAt, &item.SentAt, &item.ErrorMessage,
		); err != nil {
			return nil, fmt.Errorf("scan queued item: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// UpdateQueueStatus sets the status and updated_at for an outbound queue item.
func (db *DB) UpdateQueueStatus(id int64, status string) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		"UPDATE outbound_queue SET status = ?, updated_at = ? WHERE id = ?",
		status, now, id,
	)
	return err
}

// UpdateQueueSent marks a queue item as sent with the current timestamp.
func (db *DB) UpdateQueueSent(id int64) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		"UPDATE outbound_queue SET status = 'sent', sent_at = ?, updated_at = ? WHERE id = ?",
		now, now, id,
	)
	return err
}

// UpdateQueueFailed marks a queue item as failed with an error message.
func (db *DB) UpdateQueueFailed(id int64, errMsg string) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		"UPDATE outbound_queue SET status = 'failed', error_message = ?, updated_at = ? WHERE id = ?",
		errMsg, now, id,
	)
	return err
}

// InsertQueueItem inserts a new outbound queue item and returns its ID.
func (db *DB) InsertQueueItem(item *model.OutboundItem) (int64, error) {
	now := nowUTC()
	res, err := db.conn.Exec(
		"INSERT INTO outbound_queue (account_id, agent_id, correlation_id, status, from_addr, to_addrs, cc_addrs, subject, body_text, body_html, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		item.AccountID, item.AgentID, item.CorrelationID, item.Status,
		item.FromAddr, item.ToAddrs, item.CcAddrs, item.Subject,
		item.BodyText, item.BodyHTML, now, now,
	)
	if err != nil {
		return 0, fmt.Errorf("insert queue item: %w", err)
	}
	return res.LastInsertId()
}

// InsertDeliveryAttempt records a delivery attempt for a queue item.
func (db *DB) InsertDeliveryAttempt(queueID int64, success bool, errMsg, smtpResponse string) error {
	successInt := 0
	if success {
		successInt = 1
	}
	_, err := db.conn.Exec(
		"INSERT INTO delivery_attempts (queue_id, success, error_message, smtp_response) VALUES (?, ?, ?, ?)",
		queueID, successInt, errMsg, smtpResponse,
	)
	return err
}

// InsertHold creates a new hold record for a queued item.
func (db *DB) InsertHold(queueID, ruleID int64, reason string) error {
	_, err := db.conn.Exec(
		"INSERT INTO holds (queue_id, rule_id, reason) VALUES (?, ?, ?)",
		queueID, ruleID, reason,
	)
	return err
}

// UpdateHold updates a hold's status and records the reviewing operator.
func (db *DB) UpdateHold(holdID int64, status string, operatorID int64) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		"UPDATE holds SET status = ?, reviewer_id = ?, reviewed_at = ? WHERE id = ?",
		status, operatorID, now, holdID,
	)
	return err
}

// GetQueueIDFromHold returns the queue_id associated with a hold.
func (db *DB) GetQueueIDFromHold(holdID int64) (int64, error) {
	var queueID int64
	err := db.conn.QueryRow("SELECT queue_id FROM holds WHERE id = ?", holdID).Scan(&queueID)
	if err != nil {
		return 0, fmt.Errorf("get queue_id from hold %d: %w", holdID, err)
	}
	return queueID, nil
}

// GetAccountCredentials returns the username and password for an account.
func (db *DB) GetAccountCredentials(accountID int64) (username, password string, err error) {
	err = db.conn.QueryRow(
		"SELECT username_enc, password_enc FROM account_credentials WHERE account_id = ?",
		accountID,
	).Scan(&username, &password)
	if err != nil {
		return "", "", fmt.Errorf("get credentials for account %d: %w", accountID, err)
	}
	return username, password, nil
}

// GetAccountByID returns an account by its ID, joining mail_servers for connection details.
func (db *DB) GetAccountByID(accountID int64) (*model.Account, error) {
	row := db.conn.QueryRow(
		`SELECT a.id, a.name, a.email_address,
		        COALESCE(a.server_id, 0),
		        COALESCE(ms.name, ''),
		        COALESCE(ms.smtp_host, COALESCE(a.smtp_host, '')),
		        COALESCE(ms.smtp_port, COALESCE(a.smtp_port, 0)),
		        COALESCE(ms.smtp_tls, COALESCE(a.smtp_tls, 1)),
		        COALESCE(ms.imap_host, COALESCE(a.imap_host, '')),
		        COALESCE(ms.imap_port, COALESCE(a.imap_port, 0)),
		        COALESCE(ms.imap_tls, COALESCE(a.imap_tls, 1)),
		        a.retrieval_enabled, a.sending_enabled,
		        COALESCE(a.storage_mode, 'metadata'), a.enabled,
		        COALESCE(a.health_status, 'unknown'), a.created_at, a.updated_at
		 FROM accounts a
		 LEFT JOIN mail_servers ms ON ms.id = a.server_id
		 WHERE a.id = ?`,
		accountID,
	)
	a, err := scanAccount(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get account %d: %w", accountID, err)
	}
	return &a, nil
}

// --- IMAP retrieval queries ---

// GetEnabledRetrievalAccounts returns all accounts where enabled=1 AND retrieval_enabled=1.
func (db *DB) GetEnabledRetrievalAccounts() ([]model.Account, error) {
	rows, err := db.conn.Query(
		`SELECT a.id, a.name, a.email_address,
		        COALESCE(a.server_id, 0),
		        COALESCE(ms.name, ''),
		        COALESCE(ms.smtp_host, COALESCE(a.smtp_host, '')),
		        COALESCE(ms.smtp_port, COALESCE(a.smtp_port, 0)),
		        COALESCE(ms.smtp_tls, COALESCE(a.smtp_tls, 1)),
		        COALESCE(ms.imap_host, COALESCE(a.imap_host, '')),
		        COALESCE(ms.imap_port, COALESCE(a.imap_port, 0)),
		        COALESCE(ms.imap_tls, COALESCE(a.imap_tls, 1)),
		        a.retrieval_enabled, a.sending_enabled,
		        COALESCE(a.storage_mode, 'metadata'), a.enabled,
		        COALESCE(a.health_status, 'unknown'), a.created_at, a.updated_at
		 FROM accounts a
		 LEFT JOIN mail_servers ms ON ms.id = a.server_id
		 WHERE a.enabled = 1 AND a.retrieval_enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("query enabled retrieval accounts: %w", err)
	}
	defer rows.Close()

	var accounts []model.Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

// MessageExists returns true if a message with the given account_id and message_id already exists.
func (db *DB) MessageExists(accountID int64, messageID string) (bool, error) {
	var count int
	err := db.conn.QueryRow(
		"SELECT COUNT(*) FROM messages WHERE account_id = ? AND message_id = ?",
		accountID, messageID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check message exists: %w", err)
	}
	return count > 0, nil
}

// InsertMessage inserts a new message row and returns its ID.
func (db *DB) InsertMessage(msg *model.Message) (int64, error) {
	now := nowUTC()
	storedOnDisk := 0
	if msg.StoredOnDisk {
		storedOnDisk = 1
	}
	res, err := db.conn.Exec(
		`INSERT INTO messages
		 (account_id, message_id, imap_uid, imap_uidvalidity, folder, from_addr, to_addrs, cc_addrs, subject, date, size, content_hash, direction, retrieved_at, archive_path, stored_on_disk)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.AccountID, msg.MessageID, msg.IMAPUID, msg.IMAPUIDValidity,
		msg.Folder, msg.FromAddr, msg.ToAddrs, msg.CcAddrs,
		msg.Subject, msg.Date, msg.Size, msg.ContentHash,
		msg.Direction, now, msg.ArchivePath, storedOnDisk,
	)
	if err != nil {
		return 0, fmt.Errorf("insert message: %w", err)
	}
	return res.LastInsertId()
}

// InsertMessageBody inserts a message body (text and/or html) for the given message ID.
func (db *DB) InsertMessageBody(messageID int64, text, html string) error {
	_, err := db.conn.Exec(
		"INSERT INTO message_bodies (message_id, body_text, body_html) VALUES (?, ?, ?)",
		messageID, text, html,
	)
	if err != nil {
		return fmt.Errorf("insert message body: %w", err)
	}
	return nil
}

// Ping checks database connectivity.
func (db *DB) Ping() error {
	return db.conn.Ping()
}


// --- Audit event queries ---

// InsertAuditEvent inserts a new audit event and returns its ID.
func (db *DB) InsertAuditEvent(event *model.AuditEvent) (int64, error) {
	res, err := db.conn.Exec(
		"INSERT INTO audit_events (actor_type, actor_id, action, target_type, target_id, outcome, details_json, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		event.ActorType, event.ActorID, event.Action, event.TargetType, event.TargetID,
		event.Outcome, event.DetailsJSON, event.CorrelationID, event.CreatedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("insert audit event: %w", err)
	}
	return res.LastInsertId()
}

// ExportAuditEvents returns audit events within a date range.
// since and until are ISO 8601 date strings. If empty, no bound is applied.
func (db *DB) ExportAuditEvents(since, until string) ([]model.AuditEvent, error) {
	query := "SELECT id, actor_type, actor_id, action, COALESCE(target_type, ''), COALESCE(target_id, ''), outcome, COALESCE(details_json, ''), COALESCE(correlation_id, ''), created_at FROM audit_events"
	var conditions []string
	var args []interface{}

	if since != "" {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, since)
	}
	if until != "" {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, until)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at ASC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("export audit events: %w", err)
	}
	defer rows.Close()

	var events []model.AuditEvent
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// GetUnhealthyAccountCount returns the number of enabled accounts with a non-ok health status.
func (db *DB) GetUnhealthyAccountCount() (int, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM accounts WHERE enabled = 1 AND health_status != 'ok' AND health_status != 'unknown'").Scan(&count)
	return count, err
}

// UpdateAccountHealth updates the health_status and updated_at for an account.
func (db *DB) UpdateAccountHealth(accountID int64, status string) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		"UPDATE accounts SET health_status = ?, updated_at = ? WHERE id = ?",
		status, now, accountID,
	)
	if err != nil {
		return fmt.Errorf("update account health: %w", err)
	}
	return nil
}

// --- MCP query methods ---

// ListMessages returns messages for an account in a given folder, up to limit.
func (db *DB) ListMessages(accountID int64, folder string, limit int) ([]model.Message, error) {
	rows, err := db.conn.Query(
		`SELECT id, account_id, COALESCE(message_id, ''), COALESCE(imap_uid, 0), COALESCE(imap_uidvalidity, 0),
		        COALESCE(folder, 'INBOX'), COALESCE(from_addr, ''), COALESCE(to_addrs, ''), COALESCE(cc_addrs, ''),
		        COALESCE(subject, ''), COALESCE(date, ''), COALESCE(size, 0), COALESCE(content_hash, ''),
		        direction, retrieved_at, COALESCE(archive_path, ''), COALESCE(stored_on_disk, 0),
		        COALESCE(is_read, 0), COALESCE(is_flagged, 0)
		 FROM messages
		 WHERE account_id = ? AND folder = ?
		 ORDER BY date DESC
		 LIMIT ?`,
		accountID, folder, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list messages: %w", err)
	}
	defer rows.Close()

	var msgs []model.Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// GetMessage returns a single message by account and message row ID.
func (db *DB) GetMessage(accountID int64, messageID int64) (*model.Message, error) {
	row := db.conn.QueryRow(
		`SELECT id, account_id, COALESCE(message_id, ''), COALESCE(imap_uid, 0), COALESCE(imap_uidvalidity, 0),
		        COALESCE(folder, 'INBOX'), COALESCE(from_addr, ''), COALESCE(to_addrs, ''), COALESCE(cc_addrs, ''),
		        COALESCE(subject, ''), COALESCE(date, ''), COALESCE(size, 0), COALESCE(content_hash, ''),
		        direction, retrieved_at, COALESCE(archive_path, ''), COALESCE(stored_on_disk, 0),
		        COALESCE(is_read, 0), COALESCE(is_flagged, 0)
		 FROM messages
		 WHERE account_id = ? AND id = ?`,
		accountID, messageID,
	)
	m, err := scanMessage(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get message %d: %w", messageID, err)
	}
	return &m, nil
}

// SearchMessages searches messages by subject, from, or to fields.
func (db *DB) SearchMessages(accountID int64, query string, limit int) ([]model.Message, error) {
	pattern := "%" + query + "%"
	rows, err := db.conn.Query(
		`SELECT id, account_id, COALESCE(message_id, ''), COALESCE(imap_uid, 0), COALESCE(imap_uidvalidity, 0),
		        COALESCE(folder, 'INBOX'), COALESCE(from_addr, ''), COALESCE(to_addrs, ''), COALESCE(cc_addrs, ''),
		        COALESCE(subject, ''), COALESCE(date, ''), COALESCE(size, 0), COALESCE(content_hash, ''),
		        direction, retrieved_at, COALESCE(archive_path, ''), COALESCE(stored_on_disk, 0),
		        COALESCE(is_read, 0), COALESCE(is_flagged, 0)
		 FROM messages
		 WHERE account_id = ?
		   AND (subject LIKE ? OR from_addr LIKE ? OR to_addrs LIKE ?)
		 ORDER BY date DESC
		 LIMIT ?`,
		accountID, pattern, pattern, pattern, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("search messages: %w", err)
	}
	defer rows.Close()

	var msgs []model.Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan search result: %w", err)
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// GetMessageBody returns the text and html body for a message.
func (db *DB) GetMessageBody(messageID int64) (text, html string, err error) {
	err = db.conn.QueryRow(
		"SELECT COALESCE(body_text, ''), COALESCE(body_html, '') FROM message_bodies WHERE message_id = ?",
		messageID,
	).Scan(&text, &html)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("get message body %d: %w", messageID, err)
	}
	return text, html, nil
}

// DeleteMessage deletes a message by its ID.
func (db *DB) DeleteMessage(id int64) error {
	_, err := db.conn.Exec("DELETE FROM messages WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete message %d: %w", id, err)
	}
	return nil
}

// UpdateMessageFlag updates the is_read or is_flagged status for a message.
// Supported flags: "read" (sets is_read=1), "unread" (sets is_read=0), "flagged" (sets is_flagged=1).
func (db *DB) UpdateMessageFlag(messageID int64, flag string) error {
	var query string
	switch flag {
	case "read":
		query = "UPDATE messages SET is_read = 1 WHERE id = ?"
	case "unread":
		query = "UPDATE messages SET is_read = 0 WHERE id = ?"
	case "flagged":
		query = "UPDATE messages SET is_flagged = 1 WHERE id = ?"
	default:
		return fmt.Errorf("unsupported flag: %s", flag)
	}
	_, err := db.conn.Exec(query, messageID)
	if err != nil {
		return fmt.Errorf("update message flag %d %s: %w", messageID, flag, err)
	}
	return nil
}

// ListHolds returns holds with the given status.
func (db *DB) ListHolds(status string) ([]model.Hold, error) {
	rows, err := db.conn.Query(
		`SELECT id, queue_id, rule_id, reason, status, reviewer_id, reviewed_at, created_at
		 FROM holds
		 WHERE status = ?
		 ORDER BY created_at DESC`,
		status,
	)
	if err != nil {
		return nil, fmt.Errorf("list holds: %w", err)
	}
	defer rows.Close()

	var holds []model.Hold
	for rows.Next() {
		var h model.Hold
		if err := rows.Scan(&h.ID, &h.QueueID, &h.RuleID, &h.Reason, &h.Status, &h.ReviewerID, &h.ReviewedAt, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan hold: %w", err)
		}
		holds = append(holds, h)
	}
	return holds, rows.Err()
}

// ListAccounts returns all accounts.
func (db *DB) ListAccounts() ([]model.Account, error) {
	rows, err := db.conn.Query(
		`SELECT a.id, a.name, a.email_address,
		        COALESCE(a.server_id, 0),
		        COALESCE(ms.name, ''),
		        COALESCE(ms.smtp_host, COALESCE(a.smtp_host, '')),
		        COALESCE(ms.smtp_port, COALESCE(a.smtp_port, 0)),
		        COALESCE(ms.smtp_tls, COALESCE(a.smtp_tls, 1)),
		        COALESCE(ms.imap_host, COALESCE(a.imap_host, '')),
		        COALESCE(ms.imap_port, COALESCE(a.imap_port, 0)),
		        COALESCE(ms.imap_tls, COALESCE(a.imap_tls, 1)),
		        a.retrieval_enabled, a.sending_enabled,
		        COALESCE(a.storage_mode, 'metadata'), a.enabled,
		        COALESCE(a.health_status, 'unknown'), a.created_at, a.updated_at
		 FROM accounts a
		 LEFT JOIN mail_servers ms ON ms.id = a.server_id
		 ORDER BY a.id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var accounts []model.Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

// GetAuditByCorrelation returns audit events matching a correlation ID.
func (db *DB) GetAuditByCorrelation(correlationID string) ([]model.AuditEvent, error) {
	rows, err := db.conn.Query(
		`SELECT id, actor_type, actor_id, action, COALESCE(target_type, ''), COALESCE(target_id, ''),
		        outcome, COALESCE(details_json, ''), COALESCE(correlation_id, ''), created_at
		 FROM audit_events
		 WHERE correlation_id = ?
		 ORDER BY created_at ASC`,
		correlationID,
	)
	if err != nil {
		return nil, fmt.Errorf("get audit by correlation: %w", err)
	}
	defer rows.Close()

	var events []model.AuditEvent
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// CreateAccount inserts a new account and returns its ID.
func (db *DB) CreateAccount(a *model.Account) (int64, error) {
	now := nowUTC()
	var serverID interface{}
	if a.ServerID > 0 {
		serverID = a.ServerID
	}
	res, err := db.conn.Exec(
		`INSERT INTO accounts (name, email_address, server_id, smtp_host, smtp_port, smtp_tls, imap_host, imap_port, imap_tls, retrieval_enabled, sending_enabled, storage_mode, enabled, health_status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'unknown', ?, ?)`,
		a.Name, a.EmailAddress, serverID,
		a.SMTPHost, a.SMTPPort, boolToInt(a.SMTPTLS),
		a.IMAPHost, a.IMAPPort, boolToInt(a.IMAPTLS),
		boolToInt(a.RetrievalEnabled), boolToInt(a.SendingEnabled),
		a.StorageMode, now, now,
	)
	if err != nil {
		return 0, fmt.Errorf("create account: %w", err)
	}
	return res.LastInsertId()
}

// UpdateAccount updates an existing account's settings.
func (db *DB) UpdateAccount(a *model.Account) error {
	now := nowUTC()
	var serverID interface{}
	if a.ServerID > 0 {
		serverID = a.ServerID
	}
	_, err := db.conn.Exec(
		`UPDATE accounts SET name = ?, email_address = ?, server_id = ?,
		        retrieval_enabled = ?, sending_enabled = ?,
		        storage_mode = ?, enabled = ?, updated_at = ?
		 WHERE id = ?`,
		a.Name, a.EmailAddress, serverID,
		boolToInt(a.RetrievalEnabled), boolToInt(a.SendingEnabled),
		a.StorageMode, boolToInt(a.Enabled), now, a.ID,
	)
	if err != nil {
		return fmt.Errorf("update account %d: %w", a.ID, err)
	}
	return nil
}

// DeleteAccount deletes an account by its ID.
func (db *DB) DeleteAccount(id int64) error {
	_, err := db.conn.Exec("DELETE FROM accounts WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete account %d: %w", id, err)
	}
	return nil
}

// --- Mail server queries ---

// ListMailServers returns all mail servers ordered by ID.
func (db *DB) ListMailServers() ([]model.MailServer, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, imap_host, imap_port, imap_tls, smtp_host, smtp_port, smtp_tls, created_at, updated_at
		 FROM mail_servers ORDER BY id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list mail servers: %w", err)
	}
	defer rows.Close()

	var servers []model.MailServer
	for rows.Next() {
		var s model.MailServer
		if err := rows.Scan(
			&s.ID, &s.Name, &s.IMAPHost, &s.IMAPPort, &s.IMAPTLS,
			&s.SMTPHost, &s.SMTPPort, &s.SMTPTLS,
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan mail server: %w", err)
		}
		servers = append(servers, s)
	}
	return servers, rows.Err()
}

// CreateMailServer inserts a new mail server and returns its ID.
func (db *DB) CreateMailServer(s *model.MailServer) (int64, error) {
	now := nowUTC()
	res, err := db.conn.Exec(
		`INSERT INTO mail_servers (name, imap_host, imap_port, imap_tls, smtp_host, smtp_port, smtp_tls, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.Name, s.IMAPHost, s.IMAPPort, boolToInt(s.IMAPTLS),
		s.SMTPHost, s.SMTPPort, boolToInt(s.SMTPTLS),
		now, now,
	)
	if err != nil {
		return 0, fmt.Errorf("create mail server: %w", err)
	}
	return res.LastInsertId()
}

// GetMailServerByID returns a mail server by its ID.
func (db *DB) GetMailServerByID(id int64) (*model.MailServer, error) {
	s := &model.MailServer{}
	err := db.conn.QueryRow(
		`SELECT id, name, imap_host, imap_port, imap_tls, smtp_host, smtp_port, smtp_tls, created_at, updated_at
		 FROM mail_servers WHERE id = ?`, id,
	).Scan(
		&s.ID, &s.Name, &s.IMAPHost, &s.IMAPPort, &s.IMAPTLS,
		&s.SMTPHost, &s.SMTPPort, &s.SMTPTLS,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mail server %d: %w", id, err)
	}
	return s, nil
}

// UpdateMailServer updates an existing mail server's settings.
func (db *DB) UpdateMailServer(s *model.MailServer) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		`UPDATE mail_servers SET name = ?, imap_host = ?, imap_port = ?, imap_tls = ?,
		        smtp_host = ?, smtp_port = ?, smtp_tls = ?, updated_at = ?
		 WHERE id = ?`,
		s.Name, s.IMAPHost, s.IMAPPort, boolToInt(s.IMAPTLS),
		s.SMTPHost, s.SMTPPort, boolToInt(s.SMTPTLS), now, s.ID,
	)
	if err != nil {
		return fmt.Errorf("update mail server %d: %w", s.ID, err)
	}
	return nil
}

// DeleteMailServer deletes a mail server by its ID.
func (db *DB) DeleteMailServer(id int64) error {
	_, err := db.conn.Exec("DELETE FROM mail_servers WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete mail server %d: %w", id, err)
	}
	return nil
}

// CountAccountsForServer returns the number of accounts referencing a given server.
func (db *DB) CountAccountsForServer(serverID int64) (int, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM accounts WHERE server_id = ?", serverID).Scan(&count)
	return count, err
}

// ListAgents returns all agents.
func (db *DB) ListAgents() ([]model.Agent, error) {
	rows, err := db.conn.Query(
		`SELECT id, agent_email, display_name, enabled, created_at, updated_at
		 FROM agents ORDER BY id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	var agents []model.Agent
	for rows.Next() {
		var a model.Agent
		if err := rows.Scan(&a.ID, &a.AgentEmail, &a.DisplayName, &a.Enabled, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// CreateAgent inserts a new agent and returns its ID.
func (db *DB) CreateAgent(displayName, agentEmail string) (int64, error) {
	now := nowUTC()
	res, err := db.conn.Exec(
		"INSERT INTO agents (agent_email, display_name, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
		agentEmail, displayName, now, now,
	)
	if err != nil {
		return 0, fmt.Errorf("create agent: %w", err)
	}
	return res.LastInsertId()
}

// GetAgentByID returns a single agent by numeric ID.
func (db *DB) GetAgentByID(id int64) (*model.Agent, error) {
	a := &model.Agent{}
	err := db.conn.QueryRow(
		`SELECT id, agent_email, display_name, enabled, created_at, updated_at FROM agents WHERE id = ?`, id,
	).Scan(&a.ID, &a.AgentEmail, &a.DisplayName, &a.Enabled, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get agent by id: %w", err)
	}
	return a, nil
}

// GetAgentByName returns the agent with the given display name, or nil if not found.
func (db *DB) GetAgentByName(name string) (*model.Agent, error) {
	a := &model.Agent{}
	err := db.conn.QueryRow(
		`SELECT id, agent_email, display_name, enabled, created_at, updated_at FROM agents WHERE display_name = ?`, name,
	).Scan(&a.ID, &a.AgentEmail, &a.DisplayName, &a.Enabled, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get agent by name: %w", err)
	}
	return a, nil
}

// UpdateAgentEnabled sets the enabled flag for an agent.
func (db *DB) UpdateAgentEnabled(agentID int64, enabled bool) error {
	now := nowUTC()
	_, err := db.conn.Exec("UPDATE agents SET enabled = ?, updated_at = ? WHERE id = ?", boolToInt(enabled), now, agentID)
	return err
}

// RevokeAllTokensForAgent disables all tokens for an agent.
func (db *DB) RevokeAllTokensForAgent(agentID int64) error {
	_, err := db.conn.Exec("UPDATE agent_tokens SET enabled = 0 WHERE agent_id = ?", agentID)
	return err
}

// GetActiveTokenForAgent returns the most recently created enabled token for an agent, or nil.
func (db *DB) GetActiveTokenForAgent(agentID int64) (*model.AgentToken, error) {
	t := &model.AgentToken{}
	err := db.conn.QueryRow(
		`SELECT id, agent_id, enabled, created_at, last_used_at
		 FROM agent_tokens WHERE agent_id = ? AND enabled = 1 ORDER BY created_at DESC LIMIT 1`, agentID,
	).Scan(&t.ID, &t.AgentID, &t.Enabled, &t.CreatedAt, &t.LastUsedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// ListRules returns all rules ordered by priority.
func (db *DB) ListRules() ([]model.Rule, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, enabled, priority, layer, scope, match_criteria, action, COALESCE(explanation, ''), created_at, updated_at
		 FROM rules ORDER BY priority ASC, id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()

	var rules []model.Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// CreateRule inserts a new rule and returns its ID.
func (db *DB) CreateRule(r *model.Rule) (int64, error) {
	now := nowUTC()
	res, err := db.conn.Exec(
		`INSERT INTO rules (name, enabled, priority, layer, scope, match_criteria, action, explanation, created_at, updated_at)
		 VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Priority, r.Layer, r.Scope, r.MatchCriteria, r.Action, r.Explanation, now, now,
	)
	if err != nil {
		return 0, fmt.Errorf("create rule: %w", err)
	}
	return res.LastInsertId()
}

// UpdateRuleEnabled sets the enabled flag for a rule.
func (db *DB) UpdateRuleEnabled(ruleID int64, enabled bool) error {
	now := nowUTC()
	_, err := db.conn.Exec("UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ?", boolToInt(enabled), now, ruleID)
	return err
}

// DeleteRule deletes a single rule and cleans up FK references.
func (db *DB) DeleteRule(ruleID int64) error {
	if _, err := db.conn.Exec("DELETE FROM keyword_events WHERE rule_id = ?", ruleID); err != nil {
		return err
	}
	if _, err := db.conn.Exec("DELETE FROM rule_matches WHERE rule_id = ?", ruleID); err != nil {
		return err
	}
	if _, err := db.conn.Exec("UPDATE holds SET rule_id = NULL WHERE rule_id = ?", ruleID); err != nil {
		return err
	}
	_, err := db.conn.Exec("DELETE FROM rules WHERE id = ?", ruleID)
	return err
}

// GetRuleByID returns a single rule by ID.
func (db *DB) GetRuleByID(ruleID int64) (*model.Rule, error) {
	row := db.conn.QueryRow(
		`SELECT id, name, enabled, priority, layer, scope, match_criteria, action, COALESCE(explanation, ''), created_at, updated_at
		 FROM rules WHERE id = ?`, ruleID,
	)
	r, err := scanRule(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// UpdateRule updates an existing rule.
func (db *DB) UpdateRule(r *model.Rule) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		`UPDATE rules SET name = ?, priority = ?, layer = ?, scope = ?, match_criteria = ?, action = ?, explanation = ?, updated_at = ? WHERE id = ?`,
		r.Name, r.Priority, r.Layer, r.Scope, r.MatchCriteria, r.Action, r.Explanation, now, r.ID,
	)
	return err
}

// ImportRule inserts a rule, or skips/overwrites if a rule with the same name exists.
func (db *DB) ImportRule(r *model.Rule, upsertMode string) (imported bool, err error) {
	var existingID int64
	e := db.conn.QueryRow("SELECT id FROM rules WHERE name = ?", r.Name).Scan(&existingID)
	if e == nil {
		if upsertMode == "overwrite" {
			r.ID = existingID
			return true, db.UpdateRule(r)
		}
		return false, nil // skip
	}
	_, err = db.CreateRule(r)
	return err == nil, err
}

// ListQueueItems returns queue items with an optional status filter, up to limit.
func (db *DB) ListQueueItems(status string, limit int) ([]model.OutboundItem, error) {
	var query string
	var args []interface{}
	if status != "" {
		query = "SELECT id, account_id, agent_id, correlation_id, status, from_addr, to_addrs, COALESCE(cc_addrs, ''), subject, COALESCE(body_text, ''), COALESCE(body_html, ''), created_at, updated_at, sent_at, COALESCE(error_message, '') FROM outbound_queue WHERE status = ? ORDER BY created_at DESC LIMIT ?"
		args = []interface{}{status, limit}
	} else {
		query = "SELECT id, account_id, agent_id, correlation_id, status, from_addr, to_addrs, COALESCE(cc_addrs, ''), subject, COALESCE(body_text, ''), COALESCE(body_html, ''), created_at, updated_at, sent_at, COALESCE(error_message, '') FROM outbound_queue ORDER BY created_at DESC LIMIT ?"
		args = []interface{}{limit}
	}

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list queue items: %w", err)
	}
	defer rows.Close()

	var items []model.OutboundItem
	for rows.Next() {
		var item model.OutboundItem
		if err := rows.Scan(
			&item.ID, &item.AccountID, &item.AgentID, &item.CorrelationID,
			&item.Status, &item.FromAddr, &item.ToAddrs, &item.CcAddrs,
			&item.Subject, &item.BodyText, &item.BodyHTML,
			&item.CreatedAt, &item.UpdatedAt, &item.SentAt, &item.ErrorMessage,
		); err != nil {
			return nil, fmt.Errorf("scan queue item: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListAllHolds returns holds with an optional status filter.
func (db *DB) ListAllHolds(status string) ([]model.Hold, error) {
	var query string
	var args []interface{}
	if status != "" {
		query = `SELECT id, queue_id, rule_id, reason, status, reviewer_id, reviewed_at, created_at
		         FROM holds WHERE status = ? ORDER BY created_at DESC`
		args = []interface{}{status}
	} else {
		query = `SELECT id, queue_id, rule_id, reason, status, reviewer_id, reviewed_at, created_at
		         FROM holds ORDER BY created_at DESC`
	}

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list all holds: %w", err)
	}
	defer rows.Close()

	var holds []model.Hold
	for rows.Next() {
		var h model.Hold
		if err := rows.Scan(&h.ID, &h.QueueID, &h.RuleID, &h.Reason, &h.Status, &h.ReviewerID, &h.ReviewedAt, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan hold: %w", err)
		}
		holds = append(holds, h)
	}
	return holds, rows.Err()
}

// ListFilteredAuditEvents returns a page of audit events with optional filters and the total count.
func (db *DB) ListFilteredAuditEvents(actorType, action, fromDate, toDate string, limit, offset int) ([]model.AuditEvent, int, error) {
	var conditions []string
	var args []interface{}

	if actorType != "" {
		conditions = append(conditions, "actor_type = ?")
		args = append(args, actorType)
	}
	if action != "" {
		conditions = append(conditions, "action LIKE ?")
		args = append(args, "%"+action+"%")
	}
	if fromDate != "" {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, fromDate+"T00:00:00Z")
	}
	if toDate != "" {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, toDate+"T23:59:59Z")
	}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	if err := db.conn.QueryRow("SELECT COUNT(*) FROM audit_events"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count filtered audit events: %w", err)
	}

	queryArgs := append(args, limit, offset)
	rows, err := db.conn.Query(
		"SELECT id, actor_type, actor_id, action, COALESCE(target_type, ''), COALESCE(target_id, ''), outcome, COALESCE(details_json, ''), COALESCE(correlation_id, ''), created_at FROM audit_events"+where+" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		queryArgs...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("query filtered audit events: %w", err)
	}
	defer rows.Close()

	var events []model.AuditEvent
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

// SaveAccountCredentials inserts or updates credentials for an account.
func (db *DB) SaveAccountCredentials(accountID int64, username, password string) error {
	now := nowUTC()
	_, err := db.conn.Exec(
		`INSERT INTO account_credentials (account_id, username_enc, password_enc, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(account_id) DO UPDATE SET username_enc = excluded.username_enc, password_enc = excluded.password_enc, updated_at = excluded.updated_at`,
		accountID, username, password, now,
	)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CheckAgentCapability returns true if the given agent has a specific capability on an account.
func (db *DB) CheckAgentCapability(ctx context.Context, agentID int64, accountID int64, capability string) (bool, error) {
	var count int
	err := db.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_permissions ap
		 JOIN agents a ON a.id = ap.agent_id
		 WHERE ap.agent_id = ? AND ap.account_id = ? AND ap.capability = ? AND a.enabled = 1`,
		agentID, accountID, capability,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check agent capability: %w", err)
	}
	return count > 0, nil
}

// --- Agent token queries ---

func hashToken(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// CreateAgentToken generates a new API token for an agent and returns the plaintext value.
func (db *DB) CreateAgentToken(agentID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	plaintext := hex.EncodeToString(b)
	now := nowUTC()
	_, err := db.conn.Exec(
		"INSERT INTO agent_tokens (token_hash, agent_id, created_at) VALUES (?, ?, ?)",
		hashToken(plaintext), agentID, now,
	)
	if err != nil {
		return "", fmt.Errorf("insert agent token: %w", err)
	}
	return plaintext, nil
}

// LookupAgentToken finds an enabled agent token by its plaintext value, returning nil if not found.
func (db *DB) LookupAgentToken(plaintext string) (*model.AgentToken, error) {
	t := &model.AgentToken{}
	err := db.conn.QueryRow(
		`SELECT at.id, at.token_hash, at.agent_id, at.enabled, at.created_at, at.last_used_at,
		        a.display_name, a.agent_email
		 FROM agent_tokens at
		 JOIN agents a ON a.id = at.agent_id
		 WHERE at.token_hash = ? AND at.enabled = 1 AND a.enabled = 1`,
		hashToken(plaintext),
	).Scan(&t.ID, &t.TokenHash, &t.AgentID, &t.Enabled, &t.CreatedAt, &t.LastUsedAt,
		&t.AgentName, &t.AgentEmail)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup agent token: %w", err)
	}
	return t, nil
}

// UpdateTokenLastUsed sets the last_used_at timestamp for a token.
func (db *DB) UpdateTokenLastUsed(tokenID int64) error {
	now := nowUTC()
	_, err := db.conn.Exec("UPDATE agent_tokens SET last_used_at = ? WHERE id = ?", now, tokenID)
	return err
}

// RevokeToken disables a token so it can no longer be used for authentication.
func (db *DB) RevokeToken(tokenID int64) error {
	_, err := db.conn.Exec("UPDATE agent_tokens SET enabled = 0 WHERE id = ?", tokenID)
	return err
}

// ListTokensForAgent returns all tokens for an agent, newest first.
func (db *DB) ListTokensForAgent(agentID int64) ([]model.AgentToken, error) {
	rows, err := db.conn.Query(
		`SELECT at.id, at.agent_id, at.enabled, at.created_at, at.last_used_at
		 FROM agent_tokens at
		 WHERE at.agent_id = ? ORDER BY at.created_at DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []model.AgentToken
	for rows.Next() {
		var t model.AgentToken
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Enabled, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// ListAllTokens returns all agent tokens across all agents, grouped by agent name.
func (db *DB) ListAllTokens() ([]model.AgentToken, error) {
	rows, err := db.conn.Query(
		`SELECT at.id, at.agent_id, at.enabled, at.created_at, at.last_used_at, a.display_name
		 FROM agent_tokens at JOIN agents a ON a.id = at.agent_id
		 ORDER BY a.display_name, at.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []model.AgentToken
	for rows.Next() {
		var t model.AgentToken
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Enabled, &t.CreatedAt, &t.LastUsedAt, &t.AgentName); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// ListAccountsForAgent returns all enabled accounts the agent has at least one permission for.
func (db *DB) ListAccountsForAgent(agentID int64) ([]model.Account, error) {
	rows, err := db.conn.Query(
		`SELECT DISTINCT acc.id, acc.name, acc.email_address, COALESCE(acc.server_id, 0),
		        COALESCE(acc.smtp_host, ''), COALESCE(acc.smtp_port, 0), COALESCE(acc.smtp_tls, 1),
		        COALESCE(acc.imap_host, ''), COALESCE(acc.imap_port, 0), COALESCE(acc.imap_tls, 1),
		        acc.retrieval_enabled, acc.sending_enabled, acc.storage_mode, acc.enabled,
		        acc.health_status, acc.created_at, acc.updated_at
		 FROM accounts acc
		 JOIN agent_permissions ap ON ap.account_id = acc.id
		 WHERE ap.agent_id = ? AND acc.enabled = 1
		 ORDER BY acc.name ASC`, agentID)
	if err != nil {
		return nil, fmt.Errorf("list accounts for agent: %w", err)
	}
	defer rows.Close()
	var accounts []model.Account
	for rows.Next() {
		var a model.Account
		if err := rows.Scan(&a.ID, &a.Name, &a.EmailAddress, &a.ServerID,
			&a.SMTPHost, &a.SMTPPort, &a.SMTPTLS,
			&a.IMAPHost, &a.IMAPPort, &a.IMAPTLS,
			&a.RetrievalEnabled, &a.SendingEnabled, &a.StorageMode, &a.Enabled,
			&a.HealthStatus, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan account for agent: %w", err)
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

// --- Storage stats ---

// StorageStats holds row counts for the settings page.
type StorageStats struct {
	MessageCount     int
	BodyCount        int
	AttachmentCount  int
	AuditCount       int
	QueueCount       int
	DBSizeBytes      int64
	StorageDiskBytes int64
}

// GetStorageStats returns row counts and database size for the settings page.
func (db *DB) GetStorageStats() (*StorageStats, error) {
	s := &StorageStats{}
	queries := []struct {
		query string
		dest  *int
	}{
		{"SELECT COUNT(*) FROM messages", &s.MessageCount},
		{"SELECT COUNT(*) FROM message_bodies", &s.BodyCount},
		{"SELECT COUNT(*) FROM attachments", &s.AttachmentCount},
		{"SELECT COUNT(*) FROM audit_events", &s.AuditCount},
		{"SELECT COUNT(*) FROM outbound_queue", &s.QueueCount},
	}
	for _, q := range queries {
		if err := db.conn.QueryRow(q.query).Scan(q.dest); err != nil {
			return nil, fmt.Errorf("storage stats %s: %w", q.query, err)
		}
	}
	var pageCount, pageSize int64
	_ = db.conn.QueryRow("PRAGMA page_count").Scan(&pageCount)
	_ = db.conn.QueryRow("PRAGMA page_size").Scan(&pageSize)
	s.DBSizeBytes = pageCount * pageSize
	return s, nil
}
