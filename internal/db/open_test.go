package db

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Pragmas must apply to every pooled connection, not just the one that happened to
// serve the setup call. The concurrent queries force the pool to open more than one.
func TestOpenAppliesPragmasToPooledConnections(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer database.Close()

	const conns = 8
	var wg sync.WaitGroup
	results := make(chan [2]int, conns)

	start := make(chan struct{})
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // Release together so the pool has to open several connections.
			var busyTimeout, foreignKeys int
			if err := database.conn.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
				t.Errorf("read busy_timeout: %v", err)
				return
			}
			if err := database.conn.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
				t.Errorf("read foreign_keys: %v", err)
				return
			}
			results <- [2]int{busyTimeout, foreignKeys}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	checked := 0
	for r := range results {
		checked++
		if r[0] == 0 {
			t.Error("a pooled connection has busy_timeout=0; concurrent writers will fail immediately")
		}
		if r[1] != 1 {
			t.Errorf("a pooled connection has foreign_keys=%d, want 1", r[1])
		}
	}
	if checked != conns {
		t.Fatalf("checked %d connections, want %d", checked, conns)
	}

	var journalMode string
	if err := database.conn.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Errorf("journal_mode = %q, want wal", journalMode)
	}
}

// Concurrent writers are the real workload: the IMAP poller and the queue processor
// both write while the web server reads. With busy_timeout unset they raced to
// SQLITE_BUSY instead of waiting.
func TestConcurrentWritesDoNotReturnBusy(t *testing.T) {
	database := newTestDB(t)
	accountID := seedFullAccount(t, database, "a@example.com", false)

	const writers = 8
	const writesEach = 20

	var wg sync.WaitGroup
	errCh := make(chan error, writers*writesEach)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < writesEach; i++ {
				if err := database.MarkAccountPolled(accountID); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent write failed: %v", err)
	}
}
