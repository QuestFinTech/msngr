package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/luxemque/msngr/internal/audit"
	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
	smtpAdapter "github.com/luxemque/msngr/internal/smtp"
)

const maxConcurrency = 5

// Processor reads queued outbound items and delivers them via SMTP.
type Processor struct {
	db     *db.DB
	audit  *audit.Logger
	tickMs int
}

// NewProcessor creates a new queue processor.
func NewProcessor(database *db.DB, tickMs int) *Processor {
	return &Processor{db: database, audit: audit.NewLogger(database), tickMs: tickMs}
}

// Start begins processing the outbound queue on a recurring interval.
// It blocks until ctx is cancelled.
func (p *Processor) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(p.tickMs) * time.Millisecond)
	defer ticker.Stop()

	slog.Info("Queue processor started", "tick_ms", p.tickMs)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Queue processor stopping")
			return
		case <-ticker.C:
			p.processTick(ctx)
		}
	}
}

// processTick handles a single processing cycle.
func (p *Processor) processTick(ctx context.Context) {
	items, err := p.db.GetQueuedItems(maxConcurrency)
	if err != nil {
		slog.Error("Failed to fetch queued items", "error", err)
		return
	}
	if len(items) == 0 {
		return
	}

	slog.Info("Processing queued items", "count", len(items))

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)

	for i := range items {
		item := items[i]

		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			p.processItem(ctx, item)
		}()
	}

	wg.Wait()
}

// processItem handles delivery of a single outbound queue item.
func (p *Processor) processItem(ctx context.Context, item model.OutboundItem) {
	logger := slog.With("queue_id", item.ID, "account_id", item.AccountID, "correlation_id", item.CorrelationID)

	// Mark as sending.
	if err := p.db.UpdateQueueStatus(item.ID, StatusSending); err != nil {
		logger.Error("Failed to update status to sending", "error", err)
		return
	}

	// Load account details.
	account, err := p.db.GetAccountByID(item.AccountID)
	if err != nil {
		p.failItem(ctx, logger, item, "", "load account: "+err.Error())
		return
	}
	if account == nil {
		p.failItem(ctx, logger, item, "", "account not found")
		return
	}
	smtpAddr := net.JoinHostPort(account.SMTPHost, fmt.Sprintf("%d", account.SMTPPort))

	// Load credentials.
	username, password, err := p.db.GetAccountCredentials(item.AccountID)
	if err != nil {
		p.failItem(ctx, logger, item, smtpAddr, "load credentials: "+err.Error())
		return
	}

	// Parse recipient addresses from JSON.
	var toAddrs []string
	if err := json.Unmarshal([]byte(item.ToAddrs), &toAddrs); err != nil {
		p.failItem(ctx, logger, item, smtpAddr, "parse to_addrs: "+err.Error())
		return
	}

	var ccAddrs []string
	if item.CcAddrs != "" {
		if err := json.Unmarshal([]byte(item.CcAddrs), &ccAddrs); err != nil {
			p.failItem(ctx, logger, item, smtpAddr, "parse cc_addrs: "+err.Error())
			return
		}
	}

	// Parse attachments if present.
	var smtpAttachments []smtpAdapter.SendAttachment
	if item.AttachmentsJSON != "" {
		var atts []struct {
			Filename      string `json:"filename"`
			MimeType      string `json:"mime_type"`
			ContentBase64 string `json:"content_base64"`
		}
		if err := json.Unmarshal([]byte(item.AttachmentsJSON), &atts); err != nil {
			p.failItem(ctx, logger, item, smtpAddr, "parse attachments: "+err.Error())
			return
		}
		for _, a := range atts {
			smtpAttachments = append(smtpAttachments, smtpAdapter.SendAttachment{
				Filename:      a.Filename,
				MimeType:      a.MimeType,
				ContentBase64: a.ContentBase64,
			})
		}
	}

	// Create SMTP client and send.
	client := smtpAdapter.NewClient(account.SMTPHost, account.SMTPPort, account.SMTPTLS)
	req := &smtpAdapter.SendRequest{
		From:        item.FromAddr,
		To:          toAddrs,
		Cc:          ccAddrs,
		Subject:     item.Subject,
		Text:        item.BodyText,
		HTML:        item.BodyHTML,
		Attachments: smtpAttachments,
	}

	result := client.Send(username, password, req)

	// Record delivery attempt.
	if err := p.db.InsertDeliveryAttempt(item.ID, result.Success, result.Error, result.SMTPResponse); err != nil {
		logger.Error("Failed to record delivery attempt", "error", err)
	}

	outcome := &sendOutcome{
		item:        item,
		to:          toAddrs,
		cc:          ccAddrs,
		attachments: len(smtpAttachments),
		smtpAddr:    smtpAddr,
		messageID:   result.MessageID,
		response:    result.SMTPResponse,
	}

	if result.Success {
		if err := p.db.UpdateQueueSent(item.ID); err != nil {
			logger.Error("Failed to update status to sent", "error", err)
			return
		}
		logger.Info("Message sent successfully", "smtp_response", result.SMTPResponse, "message_id", result.MessageID)
		p.auditSend(ctx, logger, "send_completed", "success", outcome)
		return
	}

	outcome.errMsg = result.Error
	p.finishFailed(ctx, logger, outcome)
}

// failItem marks a queue item as failed before a send was attempted.
func (p *Processor) failItem(ctx context.Context, logger *slog.Logger, item model.OutboundItem, smtpAddr, errMsg string) {
	p.finishFailed(ctx, logger, &sendOutcome{
		item:     item,
		smtpAddr: smtpAddr,
		errMsg:   errMsg,
	})
}

// finishFailed records a failed delivery in the queue and in the audit trail.
func (p *Processor) finishFailed(ctx context.Context, logger *slog.Logger, outcome *sendOutcome) {
	logger.Error("Message delivery failed", "error", outcome.errMsg)
	if err := p.db.UpdateQueueFailed(outcome.item.ID, outcome.errMsg); err != nil {
		logger.Error("Failed to update status to failed", "error", err)
	}
	p.auditSend(ctx, logger, "send_failed", "error", outcome)
}

// sendOutcome carries what the audit trail needs to know about one delivery attempt.
type sendOutcome struct {
	item        model.OutboundItem
	to          []string
	cc          []string
	attachments int
	smtpAddr    string
	messageID   string
	response    string
	errMsg      string
}

// auditSend writes the terminal event for an outbound message.
//
// Without it the audit trail ends at intent: a delivered message and a silently
// dropped one look identical in the record, and the only way to tell them apart is
// to ask the recipient. Every field here is something that question would need.
func (p *Processor) auditSend(ctx context.Context, logger *slog.Logger, action, outcome string, o *sendOutcome) {
	// Recipients are parsed from the queue row when the send got far enough to parse
	// them; fall back to the raw JSON so an early failure still records who it was for.
	to, cc := o.to, o.cc
	if to == nil {
		_ = json.Unmarshal([]byte(o.item.ToAddrs), &to)
	}
	if cc == nil && o.item.CcAddrs != "" {
		_ = json.Unmarshal([]byte(o.item.CcAddrs), &cc)
	}

	attempts, err := p.db.CountDeliveryAttempts(o.item.ID)
	if err != nil {
		logger.Error("Failed to count delivery attempts", "error", err)
	}

	actorID, actorName := p.resolveAgent(o.item.AgentID)

	details := map[string]any{
		"queue_id":         o.item.ID,
		"account_id":       o.item.AccountID,
		"from":             o.item.FromAddr,
		"to":               orEmpty(to),
		"cc":               orEmpty(cc),
		"subject":          o.item.Subject,
		"attachment_count": o.attachments,
		"attempts":         attempts,
	}
	if actorName != "" {
		details["agent_display_name"] = actorName
	}
	if o.smtpAddr != "" {
		details["smtp_host"] = o.smtpAddr
	}
	if o.messageID != "" {
		details["message_id"] = "<" + o.messageID + ">"
	}
	if o.response != "" {
		details["smtp_response"] = o.response
	}
	if o.errMsg != "" {
		details["error"] = o.errMsg
	}

	if err := p.audit.LogStructured(ctx, audit.Event{
		ActorType:     "agent",
		ActorID:       actorID,
		Action:        action,
		TargetType:    "outbound_queue",
		TargetID:      fmt.Sprintf("%d", o.item.ID),
		Outcome:       outcome,
		CorrelationID: o.item.CorrelationID,
	}, details); err != nil {
		logger.Error("Failed to write send audit event", "action", action, "error", err)
	}
}

// resolveAgent maps a queue item's agent to a stable actor id and display name.
// Items queued without an agent (operator-initiated, or queued before agent_id was
// recorded) are attributed to "system".
func (p *Processor) resolveAgent(agentID *int64) (actorID, displayName string) {
	if agentID == nil || *agentID == 0 {
		return "system", ""
	}
	actorID = fmt.Sprintf("%d", *agentID)
	agent, err := p.db.GetAgentByID(*agentID)
	if err != nil || agent == nil {
		return actorID, ""
	}
	return actorID, agent.DisplayName
}

func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
