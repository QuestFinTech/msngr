package web

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/luxemque/msngr/internal/config"
	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
)

// seededServer builds a server whose database holds three weeks of traffic, so the
// usage section is exercised with real numbers rather than an empty window.
func seededServer(t *testing.T) (*Server, *model.Operator) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "seeded.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// A second handle for the timestamped inserts the exported API does not expose.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer raw.Close()

	serverID, err := database.CreateMailServer(&model.MailServer{
		Name: "Development Team Mail Server", IMAPHost: "imap.example.com", IMAPPort: 993, IMAPTLS: true,
		SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPTLS: true,
	})
	if err != nil {
		t.Fatalf("CreateMailServer: %v", err)
	}

	names := []string{"claude", "naia", "grace", "ash"}
	for i, name := range names {
		email := name + "@example.com"
		accountID, err := database.CreateAccount(&model.Account{
			Name: email, EmailAddress: email, ServerID: serverID,
			RetrievalEnabled: true, SendingEnabled: true, StorageMode: "full", Enabled: true,
		})
		if err != nil {
			t.Fatalf("CreateAccount: %v", err)
		}
		agentID, err := database.CreateAgent(name, email)
		if err != nil {
			t.Fatalf("CreateAgent: %v", err)
		}
		for _, capability := range []string{"read", "send", "download_attachment"} {
			if err := database.GrantAgentPermission(agentID, accountID, capability); err != nil {
				t.Fatalf("GrantAgentPermission: %v", err)
			}
		}
		if err := database.MarkAccountPolled(accountID); err != nil {
			t.Fatalf("MarkAccountPolled: %v", err)
		}
		// One account is broken, so the health badge path is covered.
		if i == 2 {
			if _, _, err := database.UpdateAccountHealth(accountID, "error", "login: imap: NO [AUTHENTICATIONFAILED] Authentication failed."); err != nil {
				t.Fatalf("UpdateAccountHealth: %v", err)
			}
		} else if _, _, err := database.UpdateAccountHealth(accountID, "ok", ""); err != nil {
			t.Fatalf("UpdateAccountHealth: %v", err)
		}

		for day := 0; day < 21; day++ {
			when := time.Now().UTC().AddDate(0, 0, -day)

			for n := 0; n < (day*7+i*3)%5; n++ {
				ts := when.Add(time.Duration(n) * time.Hour).Format(time.RFC3339)
				if _, err := raw.Exec(
					`INSERT INTO messages (account_id, message_id, folder, from_addr, to_addrs, cc_addrs,
					                       subject, date, size, content_hash, direction, retrieved_at, stored_on_disk)
					 VALUES (?, ?, 'INBOX', 'someone@example.com', ?, '[]', 'Sample inbound message', ?, 4096, 'abc123', 'inbound', ?, ?)`,
					accountID, fmt.Sprintf("<in-%d-%d-%d@example.com>", accountID, day, n),
					`["`+email+`"]`, ts, ts, n%2,
				); err != nil {
					t.Fatalf("seed inbound: %v", err)
				}
			}

			for n := 0; n < (day*3+i)%4; n++ {
				ts := when.Add(time.Duration(n) * time.Hour).Format(time.RFC3339)
				status, sentAt := "sent", ts
				if (day+n)%11 == 0 {
					status, sentAt = "failed", ""
				}
				if _, err := raw.Exec(
					`INSERT INTO outbound_queue (account_id, agent_id, correlation_id, status, from_addr,
					                             to_addrs, cc_addrs, subject, body_text, created_at, updated_at, sent_at)
					 VALUES (?, ?, ?, ?, ?, '["recipient@example.com"]', '[]', 'Sample outbound message', 'body', ?, ?, NULLIF(?, ''))`,
					accountID, agentID, fmt.Sprintf("corr-%d-%d-%d", accountID, day, n), status, email, ts, ts, sentAt,
				); err != nil {
					t.Fatalf("seed outbound: %v", err)
				}
			}
		}
	}

	opID, err := database.CreateOperator("Mike", "operator@example.com", "hash", "master_admin")
	if err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	op, err := database.GetOperatorByID(opID)
	if err != nil || op == nil {
		t.Fatalf("GetOperatorByID: %v", err)
	}

	return NewServer(database, nil, "127.0.0.1:0", "0.2.0", config.HardPolicyConfig{}, 60), op
}

func TestDashboardWithTrafficRendersChartAndTables(t *testing.T) {
	srv, op := seededServer(t)
	body := renderDashboard(t, srv, op, "/dashboard")

	// Bars must carry a computed height, or the chart is a row of stubs.
	barHeights := regexp.MustCompile(`\.bar-(?:in|out)-\d+ \{ height: (\d+)%; \}`).FindAllStringSubmatch(body, -1)
	if len(barHeights) == 0 {
		t.Fatal("no bar height rules were generated for the daily volume chart")
	}
	nonZero := 0
	for _, m := range barHeights {
		if m[1] != "0" {
			nonZero++
		}
	}
	if nonZero == 0 {
		t.Error("every bar in the chart has zero height despite seeded traffic")
	}

	// Per-account and per-agent rows.
	for _, want := range []string{"claude@example.com", "naia@example.com", "grace@example.com", "ash@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("account %q is missing from the usage tables", want)
		}
	}

	// The unhealthy account is called out rather than blending in.
	if !strings.Contains(body, `<span class="badge badge-inactive">error</span>`) {
		t.Error("the unhealthy account is not badged on the dashboard")
	}

	// A delivery rate should now be present.
	card := deliveryRateCard(t, body)
	if !strings.Contains(card, "%") {
		t.Errorf("delivery rate is absent despite seeded sends:\n%s", card)
	}

	// An agent with visible traffic must not be reported as never active.
	agentSection := body[strings.Index(body, "Activity by Agent"):]
	if strings.Contains(agentSection[:strings.Index(agentSection, "Storage")], "never") {
		t.Error("an agent with seeded sends is shown as never active")
	}

	if !strings.Contains(body, "</html>") {
		t.Fatal("dashboard did not render to completion")
	}

	// Writing the page out makes the layout inspectable in a browser.
	if out := os.Getenv("MSNGR_DASHBOARD_PREVIEW"); out != "" {
		if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
			t.Fatalf("write preview: %v", err)
		}
		t.Logf("dashboard preview written to %s", out)
	}
}

func TestUsageWindowNarrowsResults(t *testing.T) {
	srv, _ := seededServer(t)

	usage30, err := srv.db.GetUsageStats(30)
	if err != nil {
		t.Fatalf("GetUsageStats(30): %v", err)
	}
	usage7, err := srv.db.GetUsageStats(7)
	if err != nil {
		t.Fatalf("GetUsageStats(7): %v", err)
	}

	if usage7.Received >= usage30.Received {
		t.Errorf("7-day window (%d received) is not narrower than the 30-day one (%d)",
			usage7.Received, usage30.Received)
	}
	if usage30.Sent == 0 {
		t.Error("30-day window reports no sends despite seeded traffic")
	}
	if len(usage7.Daily) != 7 {
		t.Errorf("7-day window produced %d chart days, want 7", len(usage7.Daily))
	}
}
