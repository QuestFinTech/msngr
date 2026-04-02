package queue

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/luxemque/msngr/internal/db"
	smtpAdapter "github.com/luxemque/msngr/internal/smtp"
)

const maxConcurrency = 5

// Processor reads queued outbound items and delivers them via SMTP.
type Processor struct {
	db     *db.DB
	tickMs int
}

// NewProcessor creates a new queue processor.
func NewProcessor(database *db.DB, tickMs int) *Processor {
	return &Processor{db: database, tickMs: tickMs}
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
			p.processItem(item.ID, item.AccountID, item.FromAddr, item.ToAddrs, item.CcAddrs, item.Subject, item.BodyText, item.BodyHTML)
		}()
	}

	wg.Wait()
}

// processItem handles delivery of a single outbound queue item.
func (p *Processor) processItem(queueID, accountID int64, fromAddr, toAddrsJSON, ccAddrsJSON, subject, bodyText, bodyHTML string) {
	logger := slog.With("queue_id", queueID, "account_id", accountID)

	// Mark as sending.
	if err := p.db.UpdateQueueStatus(queueID, StatusSending); err != nil {
		logger.Error("Failed to update status to sending", "error", err)
		return
	}

	// Load account details.
	account, err := p.db.GetAccountByID(accountID)
	if err != nil {
		p.failItem(logger, queueID, "load account: "+err.Error())
		return
	}
	if account == nil {
		p.failItem(logger, queueID, "account not found")
		return
	}

	// Load credentials.
	username, password, err := p.db.GetAccountCredentials(accountID)
	if err != nil {
		p.failItem(logger, queueID, "load credentials: "+err.Error())
		return
	}

	// Parse recipient addresses from JSON.
	var toAddrs []string
	if err := json.Unmarshal([]byte(toAddrsJSON), &toAddrs); err != nil {
		p.failItem(logger, queueID, "parse to_addrs: "+err.Error())
		return
	}

	var ccAddrs []string
	if ccAddrsJSON != "" {
		if err := json.Unmarshal([]byte(ccAddrsJSON), &ccAddrs); err != nil {
			p.failItem(logger, queueID, "parse cc_addrs: "+err.Error())
			return
		}
	}

	// Create SMTP client and send.
	client := smtpAdapter.NewClient(account.SMTPHost, account.SMTPPort, account.SMTPTLS)
	req := &smtpAdapter.SendRequest{
		From:    fromAddr,
		To:      toAddrs,
		Cc:      ccAddrs,
		Subject: subject,
		Text:    bodyText,
		HTML:    bodyHTML,
	}

	result := client.Send(username, password, req)

	// Record delivery attempt.
	if err := p.db.InsertDeliveryAttempt(queueID, result.Success, result.Error, result.SMTPResponse); err != nil {
		logger.Error("Failed to record delivery attempt", "error", err)
	}

	if result.Success {
		if err := p.db.UpdateQueueSent(queueID); err != nil {
			logger.Error("Failed to update status to sent", "error", err)
			return
		}
		logger.Info("Message sent successfully")
	} else {
		p.failItem(logger, queueID, result.Error)
	}
}

// failItem marks a queue item as failed and logs the error.
func (p *Processor) failItem(logger *slog.Logger, queueID int64, errMsg string) {
	logger.Error("Message delivery failed", "error", errMsg)
	if err := p.db.UpdateQueueFailed(queueID, errMsg); err != nil {
		logger.Error("Failed to update status to failed", "error", err)
	}
}
