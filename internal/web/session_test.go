package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luxemque/msngr/internal/config"
	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
)

func newTestServer(t *testing.T) (*Server, *model.Operator) {
	t.Helper()

	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	id, err := database.CreateOperator("Test Operator", "operator@example.com", "hash", "admin")
	if err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	op, err := database.GetOperatorByID(id)
	if err != nil || op == nil {
		t.Fatalf("GetOperatorByID: %v", err)
	}

	srv := NewServer(database, nil, "127.0.0.1:0", "test", config.HardPolicyConfig{}, 60)
	return srv, op
}

func requestWithCookie(value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
	return r
}

func TestSessionRoundTrip(t *testing.T) {
	srv, op := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.setSession(rec, op)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("setSession issued no cookie")
	}
	var value string
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			value = c.Value
		}
	}
	if value == "" {
		t.Fatal("no session cookie in response")
	}

	got := srv.currentOperator(requestWithCookie(value))
	if got == nil {
		t.Fatal("a freshly issued cookie was rejected")
	}
	if got.ID != op.ID || got.Email != op.Email {
		t.Errorf("got operator %d/%s, want %d/%s", got.ID, got.Email, op.ID, op.Email)
	}
}

// The pre-signature format was exactly this, and it authenticated anyone who typed it.
func TestForgedUnsignedCookieIsRejected(t *testing.T) {
	srv, op := newTestServer(t)

	forgeries := []string{
		fmt.Sprintf("%d:%s", op.ID, op.Email),
		fmt.Sprintf("%d.%s", op.ID, op.Email),
		fmt.Sprintf("%d.%s.%d", op.ID, op.Email, time.Now().Unix()),
		fmt.Sprintf("%d.%s.%d.%s", op.ID, op.Email, time.Now().Unix(), "not-a-signature"),
		"1:operator@example.com",
	}
	for _, forged := range forgeries {
		if got := srv.currentOperator(requestWithCookie(forged)); got != nil {
			t.Errorf("forged cookie %q authenticated as operator %d", forged, got.ID)
		}
	}
}

// Tampering with the signed payload must invalidate the signature.
func TestTamperedCookieIsRejected(t *testing.T) {
	srv, op := newTestServer(t)

	value, err := srv.newSessionValue(op)
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	parts := strings.Split(value, sessionFieldSep)
	if len(parts) != 4 {
		t.Fatalf("unexpected cookie shape: %q", value)
	}

	// Point the same signature at a different operator ID.
	tampered := strings.Join([]string{"999", parts[1], parts[2], parts[3]}, sessionFieldSep)
	if got := srv.currentOperator(requestWithCookie(tampered)); got != nil {
		t.Errorf("cookie with a swapped operator id authenticated as %d", got.ID)
	}

	// Extend the issue time to defeat expiry.
	future := strconv.FormatInt(time.Now().Add(365*24*time.Hour).Unix(), 10)
	tampered = strings.Join([]string{parts[0], parts[1], future, parts[3]}, sessionFieldSep)
	if got := srv.currentOperator(requestWithCookie(tampered)); got != nil {
		t.Errorf("cookie with a rewritten timestamp authenticated as %d", got.ID)
	}
}

// A cookie signed with a different deployment's secret must not be accepted.
func TestCookieFromAnotherDeploymentIsRejected(t *testing.T) {
	first, op := newTestServer(t)
	second, _ := newTestServer(t)

	value, err := first.newSessionValue(op)
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	if got := second.currentOperator(requestWithCookie(value)); got != nil {
		t.Errorf("a cookie from another deployment authenticated as operator %d", got.ID)
	}
}

// Expiry is enforced server-side, not by trusting the browser to drop the cookie.
func TestExpiredCookieIsRejected(t *testing.T) {
	srv, op := newTestServer(t)
	srv.operatorSessionMinutes = 1

	secret, err := srv.sessionSecret()
	if err != nil {
		t.Fatalf("sessionSecret: %v", err)
	}
	stale := time.Now().Add(-2 * time.Minute).Unix()
	payload := strings.Join([]string{
		strconv.FormatInt(op.ID, 10),
		encodeEmailForTest(op.Email),
		strconv.FormatInt(stale, 10),
	}, sessionFieldSep)
	value := payload + sessionFieldSep + signSession(secret, payload)

	if got := srv.currentOperator(requestWithCookie(value)); got != nil {
		t.Errorf("an expired but correctly signed cookie authenticated as %d", got.ID)
	}
}

// Addresses contain dots, which is also the field separator; they must survive.
func TestEmailWithDotsRoundTrips(t *testing.T) {
	srv, _ := newTestServer(t)

	id, err := srv.db.CreateOperator("Dotted", "first.last@sub.example.co.uk", "hash", "admin")
	if err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	op, err := srv.db.GetOperatorByID(id)
	if err != nil || op == nil {
		t.Fatalf("GetOperatorByID: %v", err)
	}

	value, err := srv.newSessionValue(op)
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	got := srv.currentOperator(requestWithCookie(value))
	if got == nil {
		t.Fatal("a cookie for an address containing dots was rejected")
	}
	if got.Email != op.Email {
		t.Errorf("got %q, want %q", got.Email, op.Email)
	}
}

func encodeEmailForTest(email string) string {
	// Mirrors newSessionValue's encoding.
	return base64.RawURLEncoding.EncodeToString([]byte(email))
}
