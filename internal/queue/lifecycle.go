// Package queue manages the outbound message lifecycle, including state transitions,
// hold management, and SMTP delivery processing.
package queue

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
)

// Valid outbound message states.
const (
	StatusDraftRequested   = "draft_requested"
	StatusValidationFailed = "validation_failed"
	StatusQueued           = "queued"
	StatusHeld             = "held"
	StatusRejected         = "rejected"
	StatusSending          = "sending"
	StatusSent             = "sent"
	StatusFailed           = "failed"
	StatusCancelled        = "cancelled"
)

// QueueMessage inserts a new outbound item with status queued.
// If CorrelationID is empty, one is generated.
func QueueMessage(database *db.DB, item *model.OutboundItem) (int64, error) {
	if item.CorrelationID == "" {
		item.CorrelationID = generateCorrelationID()
	}
	item.Status = StatusQueued
	now := time.Now().UTC().Format(time.RFC3339)
	item.CreatedAt = now
	item.UpdatedAt = now

	return database.InsertQueueItem(item)
}

// HoldMessage transitions a queued item to held and creates a hold record.
func HoldMessage(database *db.DB, queueID, ruleID int64, reason string) error {
	if err := database.UpdateQueueStatus(queueID, StatusHeld); err != nil {
		return fmt.Errorf("update queue status to held: %w", err)
	}
	if err := database.InsertHold(queueID, ruleID, reason); err != nil {
		return fmt.Errorf("insert hold: %w", err)
	}
	return nil
}

// ApproveHold approves a hold, moving the queue item back to queued.
func ApproveHold(database *db.DB, holdID, operatorID int64) error {
	if err := database.UpdateHold(holdID, "approved", operatorID); err != nil {
		return fmt.Errorf("update hold to approved: %w", err)
	}
	// The hold record contains the queue_id; we need to look it up.
	// Use the hold's queue_id to re-queue. We pass holdID to UpdateHold which
	// returns after updating. We need to retrieve the queue_id from the hold.
	queueID, err := database.GetQueueIDFromHold(holdID)
	if err != nil {
		return fmt.Errorf("get queue id from hold: %w", err)
	}
	if err := database.UpdateQueueStatus(queueID, StatusQueued); err != nil {
		return fmt.Errorf("update queue status to queued: %w", err)
	}
	return nil
}

// RejectHold rejects a hold, moving the queue item to rejected.
func RejectHold(database *db.DB, holdID, operatorID int64) error {
	if err := database.UpdateHold(holdID, "rejected", operatorID); err != nil {
		return fmt.Errorf("update hold to rejected: %w", err)
	}
	queueID, err := database.GetQueueIDFromHold(holdID)
	if err != nil {
		return fmt.Errorf("get queue id from hold: %w", err)
	}
	if err := database.UpdateQueueStatus(queueID, StatusRejected); err != nil {
		return fmt.Errorf("update queue status to rejected: %w", err)
	}
	return nil
}

// generateCorrelationID produces a random correlation ID using crypto/rand.
func generateCorrelationID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
