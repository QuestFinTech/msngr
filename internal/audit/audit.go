// Package audit provides structured audit logging backed by SQLite.
// All security-relevant actions (sends, denials, holds, logins) are recorded
// as audit events for compliance and operational visibility.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
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

func detailsJSON(kv map[string]string) string {
	data, _ := json.Marshal(kv)
	return string(data)
}

// LogSendRequested records that an agent requested to send a message.
func (l *Logger) LogSendRequested(ctx context.Context, agentID, accountID, correlationID string) error {
	return l.Log(ctx, Event{
		ActorType:     "agent",
		ActorID:       agentID,
		Action:        "send_requested",
		TargetType:    "account",
		TargetID:      accountID,
		Outcome:       "success",
		DetailsJSON:   detailsJSON(map[string]string{"account_id": accountID}),
		CorrelationID: correlationID,
	})
}

// LogSendDenied records that a send request was denied by policy.
func (l *Logger) LogSendDenied(ctx context.Context, agentID, reason, correlationID string) error {
	return l.Log(ctx, Event{
		ActorType:     "agent",
		ActorID:       agentID,
		Action:        "send_denied",
		TargetType:    "message",
		TargetID:      "",
		Outcome:       "denied",
		DetailsJSON:   detailsJSON(map[string]string{"reason": reason}),
		CorrelationID: correlationID,
	})
}

// LogMessageHeld records that a message was held for review.
func (l *Logger) LogMessageHeld(ctx context.Context, agentID, ruleID, correlationID string) error {
	return l.Log(ctx, Event{
		ActorType:     "agent",
		ActorID:       agentID,
		Action:        "message_held",
		TargetType:    "rule",
		TargetID:      ruleID,
		Outcome:       "success",
		DetailsJSON:   detailsJSON(map[string]string{"rule_id": ruleID}),
		CorrelationID: correlationID,
	})
}

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
func (l *Logger) LogMessageDeleted(ctx context.Context, actorType, actorID, messageID string) error {
	return l.Log(ctx, Event{
		ActorType:  actorType,
		ActorID:    actorID,
		Action:     "message_deleted",
		TargetType: "message",
		TargetID:   messageID,
		Outcome:    "success",
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

