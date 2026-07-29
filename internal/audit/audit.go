// Package audit provides structured audit logging backed by SQLite.
// All security-relevant actions (sends, denials, holds, logins) are recorded
// as audit events for compliance and operational visibility.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
)

// Logger provides structured audit logging backed by the database.
type Logger struct {
	db *db.DB
}

// Event represents an auditable action before it is persisted.
type Event struct {
	ActorType     string // system, operator, agent
	ActorID       string
	Action        string
	TargetType    string
	TargetID      string
	Outcome       string // success, denied, error
	DetailsJSON   string
	CorrelationID string
}

// NewLogger creates a new audit logger.
func NewLogger(database *db.DB) *Logger {
	return &Logger{db: database}
}

// Log writes an audit event to the database.
func (l *Logger) Log(ctx context.Context, event Event) error {
	ae := &model.AuditEvent{
		ActorType:     event.ActorType,
		ActorID:       event.ActorID,
		Action:        event.Action,
		TargetType:    event.TargetType,
		TargetID:      event.TargetID,
		Outcome:       event.Outcome,
		DetailsJSON:   event.DetailsJSON,
		CorrelationID: event.CorrelationID,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	id, err := l.db.InsertAuditEvent(ae)
	if err != nil {
		slog.Error("audit log failed", "action", event.Action, "error", err)
		return err
	}
	slog.Debug("audit event recorded", "id", id, "action", event.Action, "actor", event.ActorType+"/"+event.ActorID)
	return nil
}

// LogStructured writes an audit event whose details are richer than string pairs —
// recipient lists, counts, nested values. Marshalling failures are reported rather
// than silently producing an event with empty details.
func (l *Logger) LogStructured(ctx context.Context, event Event, details map[string]any) error {
	data, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details for %s: %w", event.Action, err)
	}
	event.DetailsJSON = string(data)
	return l.Log(ctx, event)
}

func detailsJSON(kv map[string]string) string {
	data, _ := json.Marshal(kv)
	return string(data)
}

// The send lifecycle (send_requested / send_denied / message_held / send_completed /
// send_failed) is written through LogStructured by the MCP outbound tools and the queue
// processor. Those events carry recipient lists and SMTP results, which do not fit the
// string-pair helpers below, and having one path for them keeps the shape consistent.

// LogHoldApproved records that an operator approved a held message.
func (l *Logger) LogHoldApproved(ctx context.Context, operatorID, holdID string) error {
	return l.Log(ctx, Event{
		ActorType:  "operator",
		ActorID:    operatorID,
		Action:     "hold_approved",
		TargetType: "hold",
		TargetID:   holdID,
		Outcome:    "success",
	})
}

// LogHoldRejected records that an operator rejected a held message.
func (l *Logger) LogHoldRejected(ctx context.Context, operatorID, holdID string) error {
	return l.Log(ctx, Event{
		ActorType:  "operator",
		ActorID:    operatorID,
		Action:     "hold_rejected",
		TargetType: "hold",
		TargetID:   holdID,
		Outcome:    "success",
	})
}

// LogMessageDeleted records that a message was deleted.
//
// actorID must be a stable identifier — an agent's numeric ID, not its display name.
// Display names are renameable and unique only at a point in time, so an audit row
// keyed on one cannot be reliably attributed later. The name is carried alongside as
// a convenience for readers.
func (l *Logger) LogMessageDeleted(ctx context.Context, actorType, actorID, actorName, messageID string) error {
	return l.Log(ctx, Event{
		ActorType:  actorType,
		ActorID:    actorID,
		Action:     "message_deleted",
		TargetType: "message",
		TargetID:   messageID,
		Outcome:    "success",
		DetailsJSON: detailsJSON(map[string]string{
			"actor_display_name": actorName,
			"message_id":         messageID,
		}),
	})
}

// LogAccountHealthChanged records a transition in an account's connectivity health.
//
// Health used to be a last-known-value with no history, so the only question anyone
// asks during an incident — "since when?" — could only be answered from journal
// retention, if at all. Transitions are recorded here so the answer outlives the logs.
func (l *Logger) LogAccountHealthChanged(ctx context.Context, actorID string, accountID int64, email, from, to, errMsg string) error {
	outcome := "success"
	if to != "ok" {
		outcome = "error"
	}
	return l.Log(ctx, Event{
		ActorType:  "system",
		ActorID:    actorID,
		Action:     "account_health_changed",
		TargetType: "account",
		TargetID:   strconv.FormatInt(accountID, 10),
		Outcome:    outcome,
		DetailsJSON: detailsJSON(map[string]string{
			"email":      email,
			"from":       from,
			"to":         to,
			"error":      errMsg,
			"account_id": strconv.FormatInt(accountID, 10),
		}),
	})
}

// LogOperatorLogin records an operator login.
func (l *Logger) LogOperatorLogin(ctx context.Context, operatorID, email string) error {
	return l.Log(ctx, Event{
		ActorType:  "operator",
		ActorID:    operatorID,
		Action:     "operator_login",
		TargetType: "operator",
		TargetID:   operatorID,
		Outcome:    "success",
		DetailsJSON: detailsJSON(map[string]string{
			"email": email,
		}),
	})
}
