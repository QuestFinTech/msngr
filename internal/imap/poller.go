package imap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
	"github.com/luxemque/msngr/internal/storage"
)

// maxBackoff is the ceiling for exponential backoff on connection failures.
const maxBackoff = 5 * time.Minute

// Poller periodically retrieves messages from enabled IMAP accounts.
type Poller struct {
	db       *db.DB
	store    *storage.Store
	tickMs   int
	stopCh   chan struct{}
	once     sync.Once

	// Per-account backoff state, keyed by account ID.
	mu       sync.Mutex
	backoffs map[int64]time.Duration
}

// NewPoller creates a Poller that polls every tickMs milliseconds.
// The store parameter may be nil if filesystem storage is not configured.
func NewPoller(database *db.DB, store *storage.Store, tickMs int) *Poller {
	return &Poller{
		db:       database,
		store:    store,
		tickMs:   tickMs,
		stopCh:   make(chan struct{}),
		backoffs: make(map[int64]time.Duration),
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

		// Check backoff.
		p.mu.Lock()
		bo := p.backoffs[acct.ID]
		p.mu.Unlock()

		if bo > 0 {
			// Still in backoff; reduce and skip.
			p.mu.Lock()
			p.backoffs[acct.ID] = 0 // will be re-applied on next failure
			p.mu.Unlock()
			slog.Debug("imap poller: skipping account (backoff)", "account_id", acct.ID, "backoff", bo)
			continue
		}

		if err := p.pollAccount(acct); err != nil {
			slog.Error("imap poller: account poll failed", "account_id", acct.ID, "error", err)
			p.increaseBackoff(acct.ID)
			// Update health status to reflect failure.
			if hErr := p.db.UpdateAccountHealth(acct.ID, "error"); hErr != nil {
				slog.Error("imap poller: failed to update health", "account_id", acct.ID, "error", hErr)
			}
		} else {
			p.resetBackoff(acct.ID)
			if hErr := p.db.UpdateAccountHealth(acct.ID, "ok"); hErr != nil {
				slog.Error("imap poller: failed to update health", "account_id", acct.ID, "error", hErr)
			}
		}
	}
}

func (p *Poller) pollAccount(acct *model.Account) error {
	slog.Info("imap poller: polling account", "account_id", acct.ID, "email", acct.EmailAddress)

	// Get credentials.
	username, password, err := p.db.GetAccountCredentials(acct.ID)
	if err != nil {
		return fmt.Errorf("get credentials: %w", err)
	}

	// Connect.
	client, err := Connect(acct.IMAPHost, acct.IMAPPort, acct.IMAPTLS)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	// Authenticate.
	if err := client.Login(username, password); err != nil {
		return fmt.Errorf("login: %w", err)
	}

	// Select INBOX.
	if err := client.SelectFolder("INBOX"); err != nil {
		return fmt.Errorf("select inbox: %w", err)
	}

	// Fetch messages from the last 24 hours as a rolling window.
	// This is conservative; deduplication prevents re-insertion.
	since := time.Now().UTC().Add(-24 * time.Hour)
	envelopes, err := client.FetchMessages(since)
	if err != nil {
		return fmt.Errorf("fetch messages: %w", err)
	}

	slog.Info("imap poller: fetched candidates", "account_id", acct.ID, "count", len(envelopes))

	var inserted int
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

			// For "full" mode, fetch attachment metadata.
			// Note: actual attachment data download is not yet supported by the IMAP adapter.
			if acct.StorageMode == "full" {
				if _, err := client.FetchAttachments(env.UID); err != nil {
					slog.Error("imap poller: fetch attachments failed", "account_id", acct.ID, "uid", env.UID, "error", err)
				}
			}

			if content.BodyText != "" || content.BodyHTML != "" {
				archivePath, err := p.store.WriteMessage(acct.EmailAddress, env.MessageID, content)
				if err != nil {
					slog.Error("imap poller: write archive failed", "account_id", acct.ID, "message_id", env.MessageID, "error", err)
				} else {
					msg.ArchivePath = archivePath
					msg.StoredOnDisk = true
				}
			}
		}

		msgID, err := p.db.InsertMessage(msg)
		if err != nil {
			slog.Error("imap poller: insert message failed", "account_id", acct.ID, "message_id", env.MessageID, "error", err)
			continue
		}
		inserted++

		// Fallback: store body in DB when filesystem storage is not available.
		if bodyFetched && !msg.StoredOnDisk && (fetchedText != "" || fetchedHTML != "") {
			if err := p.db.InsertMessageBody(msgID, fetchedText, fetchedHTML); err != nil {
				slog.Error("imap poller: insert body failed", "account_id", acct.ID, "uid", env.UID, "error", err)
			}
		}
	}

	slog.Info("imap poller: poll complete", "account_id", acct.ID, "new_messages", inserted, "total_candidates", len(envelopes))
	return nil
}

func (p *Poller) increaseBackoff(accountID int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	current := p.backoffs[accountID]
	if current == 0 {
		current = 1 * time.Second
	} else {
		current *= 2
	}
	if current > maxBackoff {
		current = maxBackoff
	}
	p.backoffs[accountID] = current
	slog.Debug("imap poller: backoff increased", "account_id", accountID, "backoff", current)
}

func (p *Poller) resetBackoff(accountID int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.backoffs, accountID)
}
