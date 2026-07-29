package db

import (
	"path/filepath"
	"testing"
)

// newTestDB opens a scratch database with the schema applied.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return database
}

// seedAccount inserts a minimal account row to satisfy the credentials foreign key.
func seedAccount(t *testing.T, database *DB, email string) int64 {
	t.Helper()
	res, err := database.conn.Exec(
		"INSERT INTO accounts (name, email_address, created_at, updated_at) VALUES (?, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
		email, email,
	)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

// storedCredentials reads the raw column values, bypassing decryption.
func storedCredentials(t *testing.T, database *DB, accountID int64) (string, string) {
	t.Helper()
	var username, password string
	err := database.conn.QueryRow(
		"SELECT username_enc, password_enc FROM account_credentials WHERE account_id = ?", accountID,
	).Scan(&username, &password)
	if err != nil {
		t.Fatalf("read stored credentials: %v", err)
	}
	return username, password
}

func TestCredentialsRoundTripEncrypted(t *testing.T) {
	database := newTestDB(t)
	if err := database.EnableCredentialEncryption("test-key"); err != nil {
		t.Fatalf("EnableCredentialEncryption: %v", err)
	}
	accountID := seedAccount(t, database, "a@example.com")

	if err := database.SaveAccountCredentials(accountID, "user@example.com", "s3cret"); err != nil {
		t.Fatalf("SaveAccountCredentials: %v", err)
	}

	rawUser, rawPass := storedCredentials(t, database, accountID)
	if rawUser == "user@example.com" || rawPass == "s3cret" {
		t.Fatalf("credentials were stored in cleartext: username=%q password=%q", rawUser, rawPass)
	}

	username, password, err := database.GetAccountCredentials(accountID)
	if err != nil {
		t.Fatalf("GetAccountCredentials: %v", err)
	}
	if username != "user@example.com" || password != "s3cret" {
		t.Errorf("got (%q, %q), want (%q, %q)", username, password, "user@example.com", "s3cret")
	}
}

func TestCredentialsWithoutKeyStayReadable(t *testing.T) {
	database := newTestDB(t)
	accountID := seedAccount(t, database, "a@example.com")

	if err := database.SaveAccountCredentials(accountID, "user", "pass"); err != nil {
		t.Fatalf("SaveAccountCredentials: %v", err)
	}
	username, password, err := database.GetAccountCredentials(accountID)
	if err != nil {
		t.Fatalf("GetAccountCredentials: %v", err)
	}
	if username != "user" || password != "pass" {
		t.Errorf("got (%q, %q), want (%q, %q)", username, password, "user", "pass")
	}
}

// The upgrade path the live deployment takes: rows written before encryption existed
// must stay usable, and one pass must convert them.
func TestReencryptPlaintextCredentials(t *testing.T) {
	database := newTestDB(t)
	legacy := seedAccount(t, database, "legacy@example.com")
	if err := database.SaveAccountCredentials(legacy, "legacy-user", "legacy-pass"); err != nil {
		t.Fatalf("SaveAccountCredentials: %v", err)
	}

	if n, err := database.CountPlaintextCredentials(); err != nil || n != 1 {
		t.Fatalf("CountPlaintextCredentials = %d, %v; want 1, nil", n, err)
	}

	if err := database.EnableCredentialEncryption("test-key"); err != nil {
		t.Fatalf("EnableCredentialEncryption: %v", err)
	}

	// Readable before conversion.
	username, password, err := database.GetAccountCredentials(legacy)
	if err != nil {
		t.Fatalf("GetAccountCredentials before conversion: %v", err)
	}
	if username != "legacy-user" || password != "legacy-pass" {
		t.Fatalf("legacy credentials changed before conversion: (%q, %q)", username, password)
	}

	converted, err := database.ReencryptPlaintextCredentials()
	if err != nil {
		t.Fatalf("ReencryptPlaintextCredentials: %v", err)
	}
	if converted != 1 {
		t.Errorf("converted = %d, want 1", converted)
	}

	rawUser, rawPass := storedCredentials(t, database, legacy)
	if rawUser == "legacy-user" || rawPass == "legacy-pass" {
		t.Errorf("conversion left cleartext behind: username=%q password=%q", rawUser, rawPass)
	}

	username, password, err = database.GetAccountCredentials(legacy)
	if err != nil {
		t.Fatalf("GetAccountCredentials after conversion: %v", err)
	}
	if username != "legacy-user" || password != "legacy-pass" {
		t.Errorf("got (%q, %q) after conversion, want (%q, %q)", username, password, "legacy-user", "legacy-pass")
	}

	if n, err := database.CountPlaintextCredentials(); err != nil || n != 0 {
		t.Errorf("CountPlaintextCredentials = %d, %v; want 0, nil", n, err)
	}

	// A second pass has nothing to do.
	if converted, err := database.ReencryptPlaintextCredentials(); err != nil || converted != 0 {
		t.Errorf("second pass converted = %d, %v; want 0, nil", converted, err)
	}
}

// The salt is persisted, so a restart derives the same key and existing rows decrypt.
func TestCredentialSaltPersistsAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	first, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := first.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := first.EnableCredentialEncryption("test-key"); err != nil {
		t.Fatalf("EnableCredentialEncryption: %v", err)
	}
	accountID := seedAccount(t, first, "a@example.com")
	if err := first.SaveAccountCredentials(accountID, "user", "pass"); err != nil {
		t.Fatalf("SaveAccountCredentials: %v", err)
	}
	first.Close()

	second, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	if err := second.EnableCredentialEncryption("test-key"); err != nil {
		t.Fatalf("EnableCredentialEncryption after restart: %v", err)
	}
	username, password, err := second.GetAccountCredentials(accountID)
	if err != nil {
		t.Fatalf("GetAccountCredentials after restart: %v", err)
	}
	if username != "user" || password != "pass" {
		t.Errorf("got (%q, %q) after restart, want (%q, %q)", username, password, "user", "pass")
	}
}

// Migration 004's columns must exist after InitSchema, since every account query
// selects them.
func TestMigrationsAddAccountHealthColumns(t *testing.T) {
	database := newTestDB(t)

	rows, err := database.conn.Query("PRAGMA table_info(accounts)")
	if err != nil {
		t.Fatalf("PRAGMA table_info: %v", err)
	}
	defer rows.Close()

	found := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		found[name] = true
	}

	for _, col := range []string{"health_changed_at", "health_error", "last_polled_at", "delete_after_retrieval"} {
		if !found[col] {
			t.Errorf("accounts table is missing column %q after InitSchema", col)
		}
	}
}

// Re-running InitSchema must be safe; it happens on every start.
func TestInitSchemaIsIdempotent(t *testing.T) {
	database := newTestDB(t)
	for i := 0; i < 3; i++ {
		if err := database.InitSchema(); err != nil {
			t.Fatalf("InitSchema run %d: %v", i+2, err)
		}
	}
}
