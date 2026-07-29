package db

import (
	"fmt"
	"time"
)

// UsageStats summarises what the gateway has actually done over a time window, as
// opposed to how it is configured. The dashboard's existing counters answer "what
// exists"; these answer "what happened".
type UsageStats struct {
	WindowDays int
	Since      string

	// Volume over the window.
	Received int
	Sent     int
	Failed   int
	Held     int
	Denied   int

	// DeliveryRatePct is sent as a percentage of delivery attempts that reached a
	// terminal state. It is -1 when nothing was attempted, so the template can say
	// "no sends" rather than showing a misleading 0%.
	DeliveryRatePct int

	// Storage as it stands now, not over the window.
	StoredMessages int
	ArchivedOnDisk int

	Daily    []DayVolume
	Accounts []AccountUsage
	Agents   []AgentUsage
}

// DayVolume is one day's mail flow. The percentages are pre-computed against the
// busiest day so the template can draw bars without doing arithmetic.
type DayVolume struct {
	Day         string
	Received    int
	Sent        int
	ReceivedPct int
	SentPct     int
}

// AccountUsage is per-account activity over the window.
type AccountUsage struct {
	AccountID    int64
	Email        string
	Received     int
	Sent         int
	HealthStatus string
	LastPolledAt string
}

// AgentUsage is per-agent activity over the window. Counts come from the outbound
// queue and audit trail rather than from display names, which are renameable.
type AgentUsage struct {
	AgentID      int64
	DisplayName  string
	Enabled      bool
	Requested    int
	Sent         int
	Failed       int
	Held         int
	Denied       int
	LastActivity string
}

// GetUsageStats gathers activity for the last windowDays days.
func (db *DB) GetUsageStats(windowDays int) (*UsageStats, error) {
	if windowDays <= 0 {
		windowDays = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -windowDays).Format(time.RFC3339)

	stats := &UsageStats{
		WindowDays: windowDays,
		Since:      since,
		Daily:      []DayVolume{},
		Accounts:   []AccountUsage{},
		Agents:     []AgentUsage{},
	}

	// Timestamps are stored as RFC3339 text, which sorts lexicographically, so a
	// string comparison is a valid range check.
	counts := []struct {
		query string
		args  []any
		dest  *int
	}{
		{"SELECT COUNT(*) FROM messages WHERE direction = 'inbound' AND retrieved_at >= ?", []any{since}, &stats.Received},
		{"SELECT COUNT(*) FROM outbound_queue WHERE status = 'sent' AND sent_at >= ?", []any{since}, &stats.Sent},
		{"SELECT COUNT(*) FROM outbound_queue WHERE status = 'failed' AND updated_at >= ?", []any{since}, &stats.Failed},
		{"SELECT COUNT(*) FROM holds WHERE created_at >= ?", []any{since}, &stats.Held},
		{"SELECT COUNT(*) FROM audit_events WHERE action = 'send_denied' AND created_at >= ?", []any{since}, &stats.Denied},
		{"SELECT COUNT(*) FROM messages", nil, &stats.StoredMessages},
		{"SELECT COUNT(*) FROM messages WHERE stored_on_disk = 1", nil, &stats.ArchivedOnDisk},
	}
	for _, c := range counts {
		if err := db.conn.QueryRow(c.query, c.args...).Scan(c.dest); err != nil {
			return nil, fmt.Errorf("usage count: %w", err)
		}
	}

	attempted := stats.Sent + stats.Failed
	stats.DeliveryRatePct = -1
	if attempted > 0 {
		stats.DeliveryRatePct = stats.Sent * 100 / attempted
	}

	daily, err := db.dailyVolume(since, windowDays)
	if err != nil {
		return nil, err
	}
	stats.Daily = daily

	accounts, err := db.accountUsage(since)
	if err != nil {
		return nil, err
	}
	stats.Accounts = accounts

	agents, err := db.agentUsage(since)
	if err != nil {
		return nil, err
	}
	stats.Agents = agents

	return stats, nil
}

// dailyVolume returns one row per day in the window, including days with no traffic
// so the chart shows gaps rather than silently compressing them away.
func (db *DB) dailyVolume(since string, windowDays int) ([]DayVolume, error) {
	received := map[string]int{}
	sent := map[string]int{}

	rows, err := db.conn.Query(
		"SELECT substr(retrieved_at, 1, 10) AS day, COUNT(*) FROM messages WHERE direction = 'inbound' AND retrieved_at >= ? GROUP BY day",
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("daily inbound volume: %w", err)
	}
	for rows.Next() {
		var day string
		var n int
		if err := rows.Scan(&day, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan daily inbound: %w", err)
		}
		received[day] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = db.conn.Query(
		"SELECT substr(sent_at, 1, 10) AS day, COUNT(*) FROM outbound_queue WHERE status = 'sent' AND sent_at >= ? GROUP BY day",
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("daily outbound volume: %w", err)
	}
	for rows.Next() {
		var day string
		var n int
		if err := rows.Scan(&day, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan daily outbound: %w", err)
		}
		sent[day] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Cap the rendered series so a 365-day window does not produce 365 bars.
	days := windowDays
	if days > 60 {
		days = 60
	}

	daily := make([]DayVolume, 0, days)
	peak := 0
	start := time.Now().UTC().AddDate(0, 0, -(days - 1))
	for i := 0; i < days; i++ {
		day := start.AddDate(0, 0, i).Format("2006-01-02")
		v := DayVolume{Day: day, Received: received[day], Sent: sent[day]}
		if v.Received > peak {
			peak = v.Received
		}
		if v.Sent > peak {
			peak = v.Sent
		}
		daily = append(daily, v)
	}

	// Bars are scaled against the busiest day, so a quiet period still shows shape.
	if peak > 0 {
		for i := range daily {
			daily[i].ReceivedPct = daily[i].Received * 100 / peak
			daily[i].SentPct = daily[i].Sent * 100 / peak
		}
	}
	return daily, nil
}

// accountUsage returns per-account traffic over the window, including accounts with
// no traffic — an account that has gone quiet is the interesting case.
func (db *DB) accountUsage(since string) ([]AccountUsage, error) {
	rows, err := db.conn.Query(
		`SELECT a.id, a.email_address,
		        COALESCE(a.health_status, 'unknown'), COALESCE(a.last_polled_at, ''),
		        (SELECT COUNT(*) FROM messages m
		          WHERE m.account_id = a.id AND m.direction = 'inbound' AND m.retrieved_at >= ?),
		        (SELECT COUNT(*) FROM outbound_queue q
		          WHERE q.account_id = a.id AND q.status = 'sent' AND q.sent_at >= ?)
		 FROM accounts a
		 WHERE a.enabled = 1
		 ORDER BY a.email_address ASC`,
		since, since,
	)
	if err != nil {
		return nil, fmt.Errorf("account usage: %w", err)
	}
	defer rows.Close()

	usage := []AccountUsage{}
	for rows.Next() {
		var u AccountUsage
		if err := rows.Scan(&u.AccountID, &u.Email, &u.HealthStatus, &u.LastPolledAt, &u.Received, &u.Sent); err != nil {
			return nil, fmt.Errorf("scan account usage: %w", err)
		}
		usage = append(usage, u)
	}
	return usage, rows.Err()
}

// agentUsage returns per-agent activity over the window.
func (db *DB) agentUsage(since string) ([]AgentUsage, error) {
	rows, err := db.conn.Query(
		`SELECT ag.id, ag.display_name, ag.enabled,
		        (SELECT COUNT(*) FROM outbound_queue q
		          WHERE q.agent_id = ag.id AND q.created_at >= ?),
		        (SELECT COUNT(*) FROM outbound_queue q
		          WHERE q.agent_id = ag.id AND q.status = 'sent' AND q.sent_at >= ?),
		        (SELECT COUNT(*) FROM outbound_queue q
		          WHERE q.agent_id = ag.id AND q.status = 'failed' AND q.updated_at >= ?),
		        (SELECT COUNT(*) FROM holds h JOIN outbound_queue q ON q.id = h.queue_id
		          WHERE q.agent_id = ag.id AND h.created_at >= ?),
		        (SELECT COUNT(*) FROM audit_events e
		          WHERE e.actor_type = 'agent' AND e.actor_id = CAST(ag.id AS TEXT)
		            AND e.action = 'send_denied' AND e.created_at >= ?),
		        -- Last activity spans both trails. Audit rows are keyed on the numeric
		        -- agent id only since that change landed, so an agent whose history
		        -- predates it would otherwise read "never" despite visible traffic.
		        COALESCE(MAX(
		          COALESCE((SELECT MAX(e.created_at) FROM audit_events e
		            WHERE e.actor_type = 'agent' AND e.actor_id = CAST(ag.id AS TEXT)), ''),
		          COALESCE((SELECT MAX(q.created_at) FROM outbound_queue q
		            WHERE q.agent_id = ag.id), '')
		        ), '')
		 FROM agents ag
		 ORDER BY ag.display_name ASC`,
		since, since, since, since, since,
	)
	if err != nil {
		return nil, fmt.Errorf("agent usage: %w", err)
	}
	defer rows.Close()

	usage := []AgentUsage{}
	for rows.Next() {
		var u AgentUsage
		if err := rows.Scan(&u.AgentID, &u.DisplayName, &u.Enabled,
			&u.Requested, &u.Sent, &u.Failed, &u.Held, &u.Denied, &u.LastActivity); err != nil {
			return nil, fmt.Errorf("scan agent usage: %w", err)
		}
		usage = append(usage, u)
	}
	return usage, rows.Err()
}
