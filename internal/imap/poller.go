package imap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/luxemque/msngr/internal/audit"
	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
	"github.com/luxemque/msngr/internal/storage"
)

// maxBackoff is the ceiling for exponential backoff on connection failures.
const maxBackoff = 5 * time.Minute

// Poller periodically retrieves messages from enabled IMAP accounts.
type Poller struct {
	db     *db.DB
	store  *storage.Store
	audit  *audit.Logger
	tickMs int
	stopCh chan struct{}
	once   sync.Once

	// Per-account backoff state and manual-poll cooldowns, keyed by account ID.
	mu          sync.Mutex
	backoffs    map[int64]backoffState
	manualPolls map[int64]time.Time
}

// backoffState is the current backoff for one account: how long the window is, and
// when the account becomes eligible to be polled again.
type backoffState struct {
	duration time.Duration
	retryAt  time.Time
}

// NewPoller creates a Poller that polls every tickMs milliseconds.
// The store parameter may be nil if filesystem storage is not configured.
func NewPoller(database *db.DB, store *storage.Store, tickMs int) *Poller {
	return &Poller{
		db:          database,
		store:       store,
		audit:       audit.NewLogger(database),
		tickMs:      tickMs,
		stopCh:      make(chan struct{}),
		backoffs:    make(map[int64]backoffState),
		manualPolls: make(map[int64]time.Time),
	}
}

// Start launches the polling loop in a background goroutine. It blocks until
// the context is cancelled or Stop is called.
func (p *Poller) Start(ctx context.Context) {
	go p.run(ctx)
}

// Stop signals the poller to stop.
func (p *Poller) Stop() {
	p.once.Do(func() {
		close(p.stopCh)
	})
}

func (p *Poller) run(ctx context.Context) {
	slog.Info("imap poller: starting", "interval_ms", p.tickMs)

	for {
		p.tick()

		// Add jitter: random 0-10% of the tick interval.
		jitter := time.Duration(rand.Int63n(int64(p.tickMs)/10+1)) * time.Millisecond
		wait := time.Duration(p.tickMs)*time.Millisecond + jitter

		select {
		case <-ctx.Done():
			slog.Info("imap poller: context cancelled, stopping")
			return
		case <-p.stopCh:
			slog.Info("imap poller: stop requested")
			return
		case <-time.After(wait):
			// next tick
		}
	}
}

func (p *Poller) tick() {
	accounts, err := p.db.GetEnabledRetrievalAccounts()
	if err != nil {
		slog.Error("imap poller: failed to get accounts", "error", err)
		return
	}

	if len(accounts) == 0 {
		return
	}

	slog.Debug("imap poller: polling accounts", "count", len(accounts))

	for i := range accounts {
		acct := &accounts[i]

		if until, backoff, skip := p.inBackoff(acct.ID); skip {
			slog.Debug("imap poller: skipping account (backoff)",
				"account_id", acct.ID, "backoff", backoff, "retry_at", until.UTC().Format(time.RFC3339))
			continue
		}

		_, pollErr := p.pollAccount(acct)
		if pollErr != nil {
			slog.Error("imap poller: account poll failed", "account_id", acct.ID, "error", pollErr)
			p.increaseBackoff(acct.ID)
			p.recordHealth(acct, "error", pollErr.Error())
		} else {
			p.resetBackoff(acct.ID)
			p.recordHealth(acct, "ok", "")
		}

		if err := p.db.MarkAccountPolled(acct.ID); err != nil {
			slog.Error("imap poller: failed to record poll time", "account_id", acct.ID, "error", err)
		}
	}
}

// minManualPollInterval is the shortest gap between two caller-triggered polls of the
// same account. Retrieval is a network round trip against someone else's mail server;
// an agent in a loop should not be able to turn that into a hammer.
const minManualPollInterval = 10 * time.Second

// ErrPollTooSoon is returned when a manual poll is requested inside the cooldown.
var ErrPollTooSoon = errors.New("account was polled too recently")

// PollNow retrieves one account immediately instead of waiting for the next tick, and
// reports how many new messages it stored.
//
// It exists so an empty inbox can be trusted: without it a caller reading no messages
// cannot tell whether the mailbox is empty or the gateway has not looked yet.
func (p *Poller) PollNow(accountID int64) (int, error) {
	acct, err := p.db.GetAccountByID(accountID)
	if err != nil {
		return 0, fmt.Errorf("look up account: %w", err)
	}
	if acct == nil {
		return 0, fmt.Errorf("account %d not found", accountID)
	}
	if !acct.Enabled || !acct.RetrievalEnabled {
		return 0, fmt.Errorf("retrieval is not enabled for account %d", accountID)
	}

	if !p.claimManualPoll(accountID) {
		return 0, ErrPollTooSoon
	}

	inserted, pollErr := p.pollAccount(acct)
	if pollErr != nil {
		p.increaseBackoff(acct.ID)
		p.recordHealth(acct, "error", pollErr.Error())
	} else {
		p.resetBackoff(acct.ID)
		p.recordHealth(acct, "ok", "")
	}
	if err := p.db.MarkAccountPolled(acct.ID); err != nil {
		slog.Error("imap poller: failed to record poll time", "account_id", acct.ID, "error", err)
	}
	return inserted, pollErr
}

// claimManualPoll reports whether a manual poll may run now, recording the attempt.
func (p *Poller) claimManualPoll(accountID int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if last, ok := p.manualPolls[accountID]; ok && time.Since(last) < minManualPollInterval {
		return false
	}
	p.manualPolls[accountID] = time.Now()
	return true
}

// recordHealth persists the observed health and audits genuine transitions.
func (p *Poller) recordHealth(acct *model.Account, status, errMsg string) {
	changed, previous, err := p.db.UpdateAccountHealth(acct.ID, status, errMsg)
	if err != nil {
		slog.Error("imap poller: failed to update health", "account_id", acct.ID, "error", err)
		return
	}
	if !changed {
		return
	}
	slog.Info("imap poller: account health changed",
		"account_id", acct.ID, "email", acct.EmailAddress, "from", previous, "to", status, "error", errMsg)
	if err := p.audit.LogAccountHealthChanged(context.Background(), "imap-poller", acct.ID, acct.EmailAddress, previous, status, errMsg); err != nil {
		slog.Error("imap poller: failed to audit health change", "account_id", acct.ID, "error", err)
	}
}

func (p *Poller) pollAccount(acct *model.Account) (int, error) {
	slog.Info("imap poller: polling account", "account_id", acct.ID, "email", acct.EmailAddress)

	// Get credentials.
	username, password, err := p.db.GetAccountCredentials(acct.ID)
	if err != nil {
		return 0, fmt.Errorf("get credentials: %w", err)
	}

	// Connect.
	client, err := Connect(acct.IMAPHost, acct.IMAPPort, acct.IMAPTLS)
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	// Authenticate.
	if err := client.Login(username, password); err != nil {
		return 0, fmt.Errorf("login: %w", err)
	}

	// Select INBOX.
	if err := client.SelectFolder("INBOX"); err != nil {
		return 0, fmt.Errorf("select inbox: %w", err)
	}

	// Fetch messages from the last 24 hours as a rolling window.
	// This is conservative; deduplication prevents re-insertion.
	since := time.Now().UTC().Add(-24 * time.Hour)
	envelopes, err := client.FetchMessages(since)
	if err != nil {
		return 0, fmt.Errorf("fetch messages: %w", err)
	}

	slog.Info("imap poller: fetched candidates", "account_id", acct.ID, "count", len(envelopes))

	var inserted int
	var retrievedUIDs []uint32 // UIDs successfully retrieved (for delete-after-retrieval)
	for _, env := range envelopes {
		// Generate a synthetic Message-ID when the envelope lacks one,
		// using IMAP UID + UIDValidity to avoid UNIQUE constraint collisions.
		if env.MessageID == "" {
			env.MessageID = fmt.Sprintf("<synthetic-%d-%d@msngr>", env.UIDValidity, env.UID)
		}

		// Deduplication: skip if message_id + account_id already exists.
		exists, err := p.db.MessageExists(acct.ID, env.MessageID)
		if err != nil {
			slog.Error("imap poller: dedup check failed", "account_id", acct.ID, "message_id", env.MessageID, "error", err)
			continue
		}
		if exists {
			continue
		}

		toJSON, _ := json.Marshal(env.To)
		ccJSON, _ := json.Marshal(env.Cc)

		msg := &model.Message{
			AccountID:       acct.ID,
			MessageID:       env.MessageID,
			IMAPUID:         int64(env.UID),
			IMAPUIDValidity: int64(env.UIDValidity),
			Folder:          "INBOX",
			FromAddr:        env.From,
			ToAddrs:         string(toJSON),
			CcAddrs:         string(ccJSON),
			Subject:         env.Subject,
			Date:            env.Date.UTC().Format(time.RFC3339),
			Size:            env.Size,
			Direction:       "inbound",
		}

		// Optionally fetch body based on storage mode.
		var fetchedText, fetchedHTML string
		var bodyFetched bool
		if acct.StorageMode == "body" || acct.StorageMode == "full" {
			text, html, err := client.FetchBody(env.UID)
			if err != nil {
				slog.Error("imap poller: fetch body failed", "account_id", acct.ID, "uid", env.UID, "error", err)
			} else {
				fetchedText = text
				fetchedHTML = html
				bodyFetched = true
			}
		}

		// Write to filesystem storage if available.
		if bodyFetched && p.store != nil {
			content := &storage.MessageContent{
				BodyText: fetchedText,
				BodyHTML: fetchedHTML,
			}

			// For "full" mode, fetch actual attachment data and include in the archive.
			if acct.StorageMode == "full" {
				attData, err := client.FetchAttachmentData(env.UID)
				if err != nil {
					slog.Error("imap poller: fetch attachment data failed", "account_id", acct.ID, "uid", env.UID, "error", err)
				}
				for _, att := range attData {
					content.Attachments = append(content.Attachments, storage.AttachmentContent{
						Filename: att.Filename,
						Data:     att.Data,
					})
				}
			}

			if content.BodyText != "" || content.BodyHTML != "" {
				archivePath, err := p.store.WriteMessage(acct.EmailAddress, env.MessageID, content)
				if err != nil {
					slog.Error("imap poller: write archive failed", "account_id", acct.ID, "message_id", env.MessageID, "error", err)
				} else {
					msg.ArchivePath = archivePath
					msg.StoredOnDisk = true
					// Hash what was stored. Storage modes that keep no content leave this
					// empty rather than presenting a hash of nothing as tamper-evidence.
					msg.ContentHash = storage.ContentHash(content)
				}
			}
		}

		msgID, err := p.db.InsertMessage(msg)
		if err != nil {
			slog.Error("imap poller: insert message failed", "account_id", acct.ID, "message_id", env.MessageID, "error", err)
			continue
		}
		inserted++
		retrievedUIDs = append(retrievedUIDs, env.UID)

		// Fallback: store body in DB when filesystem storage is not available.
		if bodyFetched && !msg.StoredOnDisk && (fetchedText != "" || fetchedHTML != "") {
			if err := p.db.InsertMessageBody(msgID, fetchedText, fetchedHTML); err != nil {
				slog.Error("imap poller: insert body failed", "account_id", acct.ID, "uid", env.UID, "error", err)
			}
		}
	}

	// Delete retrieved messages from the mail server if configured.
	if acct.DeleteAfterRetrieval && len(retrievedUIDs) > 0 {
		if err := client.DeleteMessages(retrievedUIDs); err != nil {
			slog.Error("imap poller: delete after retrieval failed", "account_id", acct.ID, "count", len(retrievedUIDs), "error", err)
		} else {
			slog.Info("imap poller: deleted retrieved messages from server", "account_id", acct.ID, "count", len(retrievedUIDs))
		}
	}

	slog.Info("imap poller: poll complete", "account_id", acct.ID, "new_messages", inserted, "total_candidates", len(envelopes))
	return inserted, nil
}

// inBackoff reports whether the account is still inside its backoff window.
//
// The window is held as an absolute retry time rather than a countdown: an earlier
// implementation stored only a duration and cleared it on sight, so a persistently
// failing account was retried every other tick forever and the doubling never took
// effect. A broken account should get quieter, not stay loud.
func (p *Poller) inBackoff(accountID int64) (retryAt time.Time, backoff time.Duration, skip bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	state, ok := p.backoffs[accountID]
	if !ok {
		return time.Time{}, 0, false
	}
	if time.Now().Before(state.retryAt) {
		return state.retryAt, state.duration, true
	}
	return state.retryAt, state.duration, false
}

func (p *Poller) increaseBackoff(accountID int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	next := p.backoffs[accountID].duration
	if next == 0 {
		next = 1 * time.Second
	} else {
		next *= 2
	}
	if next > maxBackoff {
		next = maxBackoff
	}
	p.backoffs[accountID] = backoffState{duration: next, retryAt: time.Now().Add(next)}
	slog.Debug("imap poller: backoff increased", "account_id", accountID, "backoff", next)
}

func (p *Poller) resetBackoff(accountID int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.backoffs, accountID)
}
