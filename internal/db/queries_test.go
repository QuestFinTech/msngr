package db

import (
	"context"
	"testing"

	"github.com/luxemque/msngr/internal/model"
)

func seedServer(t *testing.T, database *DB) int64 {
	t.Helper()
	id, err := database.CreateMailServer(&model.MailServer{
		Name: "test server", IMAPHost: "imap.example.com", IMAPPort: 993, IMAPTLS: true,
		SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPTLS: true,
	})
	if err != nil {
		t.Fatalf("CreateMailServer: %v", err)
	}
	return id
}

func seedFullAccount(t *testing.T, database *DB, email string, deleteAfterRetrieval bool) int64 {
	t.Helper()
	id, err := database.CreateAccount(&model.Account{
		Name: email, EmailAddress: email, ServerID: seedServer(t, database),
		RetrievalEnabled: true, SendingEnabled: true,
		DeleteAfterRetrieval: deleteAfterRetrieval, StorageMode: "full", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	return id
}

// The regression Claude reported: the agent-scoped account query dropped
// delete_after_retrieval and server_name, so a destructive setting was reported as
// false to every agent that asked.
func TestListAccountsForAgentReportsAllFields(t *testing.T) {
	database := newTestDB(t)
	accountID := seedFullAccount(t, database, "agent@example.com", true)

	agentID, err := database.CreateAgent("Test Agent", "agent@example.com")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := database.GrantAgentPermission(agentID, accountID, "read"); err != nil {
		t.Fatalf("GrantAgentPermission: %v", err)
	}

	accounts, err := database.ListAccountsForAgent(agentID)
	if err != nil {
		t.Fatalf("ListAccountsForAgent: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(accounts))
	}
	got := accounts[0]

	if !got.DeleteAfterRetrieval {
		t.Error("delete_after_retrieval reported as false for an account that has it enabled")
	}
	if got.ServerName == "" {
		t.Error("server_name is empty; the mail_servers join is not being read")
	}
	if got.IMAPHost != "imap.example.com" || got.SMTPPort != 587 {
		t.Errorf("server connection details wrong: imap=%q smtp_port=%d", got.IMAPHost, got.SMTPPort)
	}
	if got.StorageMode != "full" {
		t.Errorf("storage_mode = %q, want %q", got.StorageMode, "full")
	}

	// The agent-scoped view must agree with the canonical one.
	canonical, err := database.GetAccountByID(accountID)
	if err != nil {
		t.Fatalf("GetAccountByID: %v", err)
	}
	if canonical.DeleteAfterRetrieval != got.DeleteAfterRetrieval || canonical.ServerName != got.ServerName {
		t.Errorf("agent-scoped view disagrees with GetAccountByID: %+v vs %+v", got, *canonical)
	}
}

func TestListAccountsForAgentExcludesUnpermittedAccounts(t *testing.T) {
	database := newTestDB(t)
	permitted := seedFullAccount(t, database, "permitted@example.com", false)
	seedFullAccount(t, database, "other@example.com", false)

	agentID, err := database.CreateAgent("Test Agent", "agent@example.com")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := database.GrantAgentPermission(agentID, permitted, "read"); err != nil {
		t.Fatalf("GrantAgentPermission: %v", err)
	}

	accounts, err := database.ListAccountsForAgent(agentID)
	if err != nil {
		t.Fatalf("ListAccountsForAgent: %v", err)
	}
	if len(accounts) != 1 || accounts[0].ID != permitted {
		t.Fatalf("got %d accounts %+v, want only the permitted one", len(accounts), accounts)
	}
}

func TestAccountHealthTransitions(t *testing.T) {
	database := newTestDB(t)
	accountID := seedFullAccount(t, database, "a@example.com", false)

	// unknown -> error is a transition.
	changed, previous, err := database.UpdateAccountHealth(accountID, "error", "login failed")
	if err != nil {
		t.Fatalf("UpdateAccountHealth: %v", err)
	}
	if !changed || previous != "unknown" {
		t.Fatalf("first transition: changed=%v previous=%q, want true, %q", changed, previous, "unknown")
	}

	acct, err := database.GetAccountByID(accountID)
	if err != nil {
		t.Fatalf("GetAccountByID: %v", err)
	}
	firstChangedAt := acct.HealthChangedAt
	if firstChangedAt == "" {
		t.Fatal("health_changed_at was not set on transition")
	}
	if acct.HealthError != "login failed" {
		t.Errorf("health_error = %q, want %q", acct.HealthError, "login failed")
	}

	// error -> error is not a transition, and must not move health_changed_at.
	changed, _, err = database.UpdateAccountHealth(accountID, "error", "login failed")
	if err != nil {
		t.Fatalf("UpdateAccountHealth: %v", err)
	}
	if changed {
		t.Error("repeating the same status was reported as a transition")
	}
	acct, _ = database.GetAccountByID(accountID)
	if acct.HealthChangedAt != firstChangedAt {
		t.Errorf("health_changed_at moved on a non-transition: %q -> %q", firstChangedAt, acct.HealthChangedAt)
	}

	// Same status with a new reason refreshes the detail without claiming a transition.
	changed, _, err = database.UpdateAccountHealth(accountID, "error", "connection refused")
	if err != nil {
		t.Fatalf("UpdateAccountHealth: %v", err)
	}
	if changed {
		t.Error("a changed error message was reported as a status transition")
	}
	acct, _ = database.GetAccountByID(accountID)
	if acct.HealthError != "connection refused" {
		t.Errorf("health_error = %q, want the refreshed reason", acct.HealthError)
	}
	if acct.HealthChangedAt != firstChangedAt {
		t.Error("health_changed_at moved when only the reason changed")
	}

	// Recovery is a transition, and clears the reason.
	changed, previous, err = database.UpdateAccountHealth(accountID, "ok", "")
	if err != nil {
		t.Fatalf("UpdateAccountHealth: %v", err)
	}
	if !changed || previous != "error" {
		t.Errorf("recovery: changed=%v previous=%q, want true, %q", changed, previous, "error")
	}
	acct, _ = database.GetAccountByID(accountID)
	if acct.HealthError != "" {
		t.Errorf("health_error = %q after recovery, want empty", acct.HealthError)
	}
}

func TestListUnhealthyAccounts(t *testing.T) {
	database := newTestDB(t)
	broken := seedFullAccount(t, database, "broken@example.com", false)
	healthy := seedFullAccount(t, database, "healthy@example.com", false)

	if _, _, err := database.UpdateAccountHealth(broken, "error", "auth failed"); err != nil {
		t.Fatalf("UpdateAccountHealth: %v", err)
	}
	if _, _, err := database.UpdateAccountHealth(healthy, "ok", ""); err != nil {
		t.Fatalf("UpdateAccountHealth: %v", err)
	}

	unhealthy, err := database.ListUnhealthyAccounts()
	if err != nil {
		t.Fatalf("ListUnhealthyAccounts: %v", err)
	}
	if len(unhealthy) != 1 || unhealthy[0].ID != broken {
		t.Fatalf("got %+v, want only the broken account", unhealthy)
	}
	if unhealthy[0].HealthError != "auth failed" || unhealthy[0].HealthChangedAt == "" {
		t.Errorf("unhealthy account is missing the reason or the since-when: %+v", unhealthy[0])
	}

	count, err := database.GetUnhealthyAccountCount()
	if err != nil {
		t.Fatalf("GetUnhealthyAccountCount: %v", err)
	}
	if count != len(unhealthy) {
		t.Errorf("count %d disagrees with list length %d", count, len(unhealthy))
	}
}

func TestMarkAccountPolledDoesNotTouchUpdatedAt(t *testing.T) {
	database := newTestDB(t)
	accountID := seedFullAccount(t, database, "a@example.com", false)

	before, err := database.GetAccountByID(accountID)
	if err != nil {
		t.Fatalf("GetAccountByID: %v", err)
	}
	if err := database.MarkAccountPolled(accountID); err != nil {
		t.Fatalf("MarkAccountPolled: %v", err)
	}
	after, err := database.GetAccountByID(accountID)
	if err != nil {
		t.Fatalf("GetAccountByID: %v", err)
	}

	if after.LastPolledAt == "" {
		t.Error("last_polled_at was not set")
	}
	if after.UpdatedAt != before.UpdatedAt {
		t.Errorf("polling rewrote updated_at (%q -> %q); it must mean 'last changed'", before.UpdatedAt, after.UpdatedAt)
	}
}

func TestGetQueueItemForAgentIsScopedByPermission(t *testing.T) {
	database := newTestDB(t)
	accountID := seedFullAccount(t, database, "a@example.com", false)

	permitted, err := database.CreateAgent("Permitted", "permitted@example.com")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	outsider, err := database.CreateAgent("Outsider", "outsider@example.com")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := database.GrantAgentPermission(permitted, accountID, "send"); err != nil {
		t.Fatalf("GrantAgentPermission: %v", err)
	}

	queueID, err := database.InsertQueueItem(&model.OutboundItem{
		AccountID: accountID, AgentID: &permitted, CorrelationID: "corr-1", Status: "queued",
		FromAddr: "a@example.com", ToAddrs: `["b@example.com"]`, CcAddrs: "[]", Subject: "Hi",
		BodyText: "body",
	})
	if err != nil {
		t.Fatalf("InsertQueueItem: %v", err)
	}
	if err := database.InsertDeliveryAttempt(queueID, true, "", "250 2.0.0 Ok: queued as ABC"); err != nil {
		t.Fatalf("InsertDeliveryAttempt: %v", err)
	}

	ctx := context.Background()

	item, err := database.GetQueueItemForAgent(ctx, queueID, permitted)
	if err != nil {
		t.Fatalf("GetQueueItemForAgent: %v", err)
	}
	if item == nil {
		t.Fatal("permitted agent could not see its own queue item")
	}
	if item.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", item.Attempts)
	}
	if item.LastSMTPResponse != "250 2.0.0 Ok: queued as ABC" {
		t.Errorf("last_smtp_response = %q, want the recorded server reply", item.LastSMTPResponse)
	}
	if item.CorrelationID != "corr-1" {
		t.Errorf("correlation_id = %q, want %q", item.CorrelationID, "corr-1")
	}

	if item, err := database.GetQueueItemForAgent(ctx, queueID, outsider); err != nil {
		t.Fatalf("GetQueueItemForAgent for outsider: %v", err)
	} else if item != nil {
		t.Error("an agent with no permission on the account could read the queue item")
	}

	if item, err := database.GetQueueItemForAgent(ctx, 99999, permitted); err != nil {
		t.Fatalf("GetQueueItemForAgent for missing id: %v", err)
	} else if item != nil {
		t.Error("a non-existent queue id returned an item")
	}
}

func TestGetQueueItemForAgentReportsHold(t *testing.T) {
	database := newTestDB(t)
	accountID := seedFullAccount(t, database, "a@example.com", false)
	agentID, err := database.CreateAgent("Agent", "agent@example.com")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := database.GrantAgentPermission(agentID, accountID, "send"); err != nil {
		t.Fatalf("GrantAgentPermission: %v", err)
	}

	queueID, err := database.InsertQueueItem(&model.OutboundItem{
		AccountID: accountID, AgentID: &agentID, CorrelationID: "corr-2", Status: "held",
		FromAddr: "a@example.com", ToAddrs: `["b@example.com"]`, CcAddrs: "[]", Subject: "Held",
	})
	if err != nil {
		t.Fatalf("InsertQueueItem: %v", err)
	}
	if err := database.InsertHold(queueID, 0, "external recipient"); err != nil {
		t.Fatalf("InsertHold: %v", err)
	}

	item, err := database.GetQueueItemForAgent(context.Background(), queueID, agentID)
	if err != nil {
		t.Fatalf("GetQueueItemForAgent: %v", err)
	}
	if item == nil {
		t.Fatal("held item not visible")
	}
	if item.HoldStatus != "pending" || item.HoldReason != "external recipient" {
		t.Errorf("hold not reported: status=%q reason=%q", item.HoldStatus, item.HoldReason)
	}
	if item.Attempts != 0 {
		t.Errorf("attempts = %d for a never-attempted item, want 0", item.Attempts)
	}
}

func TestListRetrievedFolders(t *testing.T) {
	database := newTestDB(t)
	accountID := seedFullAccount(t, database, "a@example.com", false)

	folders, err := database.ListRetrievedFolders(accountID)
	if err != nil {
		t.Fatalf("ListRetrievedFolders: %v", err)
	}
	if len(folders) != 0 {
		t.Errorf("got %v for an account with no messages, want empty", folders)
	}

	if _, err := database.InsertMessage(&model.Message{
		AccountID: accountID, MessageID: "<a@example.com>", Folder: "INBOX",
		FromAddr: "s@example.com", ToAddrs: "[]", CcAddrs: "[]", Subject: "Hi",
		Date: "2026-01-01T00:00:00Z", Direction: "inbound",
	}); err != nil {
		t.Fatalf("InsertMessage: %v", err)
	}

	folders, err = database.ListRetrievedFolders(accountID)
	if err != nil {
		t.Fatalf("ListRetrievedFolders: %v", err)
	}
	if len(folders) != 1 || folders[0] != "INBOX" {
		t.Errorf("got %v, want [INBOX]", folders)
	}
}

// A nil slice marshals to JSON null, which an agent reads as "no such thing" rather
// than "none".
func TestListQueriesReturnEmptySlicesNotNil(t *testing.T) {
	database := newTestDB(t)
	accountID := seedFullAccount(t, database, "a@example.com", false)
	agentID, err := database.CreateAgent("Agent", "agent@example.com")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	msgs, err := database.ListMessages(accountID, "INBOX", 10)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if msgs == nil {
		t.Error("ListMessages returned nil; it must return an empty slice")
	}

	found, err := database.SearchMessages(accountID, "anything", 10)
	if err != nil {
		t.Fatalf("SearchMessages: %v", err)
	}
	if found == nil {
		t.Error("SearchMessages returned nil; it must return an empty slice")
	}

	holds, err := database.ListHolds("pending")
	if err != nil {
		t.Fatalf("ListHolds: %v", err)
	}
	if holds == nil {
		t.Error("ListHolds returned nil; it must return an empty slice")
	}

	accounts, err := database.ListAccountsForAgent(agentID)
	if err != nil {
		t.Fatalf("ListAccountsForAgent: %v", err)
	}
	if accounts == nil {
		t.Error("ListAccountsForAgent returned nil; it must return an empty slice")
	}

	events, err := database.GetAuditByCorrelation("nope")
	if err != nil {
		t.Fatalf("GetAuditByCorrelation: %v", err)
	}
	if events == nil {
		t.Error("GetAuditByCorrelation returned nil; it must return an empty slice")
	}
}
