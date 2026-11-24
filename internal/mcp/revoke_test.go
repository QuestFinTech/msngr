package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luxemque/msngr/internal/db"
)

func newRevokeTestServer(t *testing.T) (*Server, *db.DB, int64, string) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	agentID, err := database.CreateAgent("Test", "test@example.invalid")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	plain, err := database.CreateAgentToken(agentID)
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	return NewServer(database, nil, nil, "test", 60), database, agentID, plain
}

// authed sends one request through authMiddleware and reports whether it was authenticated.
func authed(s *Server, plain string) bool {
	var got bool
	h := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = getSession(r.Context()) != nil
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+plain)
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

// A revoked token must stop authenticating at once, even though the first request cached a session.
func TestRevokedTokenRefusedDespiteCachedSession(t *testing.T) {
	s, database, agentID, plain := newRevokeTestServer(t)
	if !authed(s, plain) {
		t.Fatal("valid token should authenticate")
	}
	if !authed(s, plain) {
		t.Fatal("valid token should authenticate from the cache")
	}
	if err := database.RevokeAllTokensForAgent(agentID); err != nil {
		t.Fatal(err)
	}
	if authed(s, plain) {
		t.Fatal("revoked token still authenticated from the session cache")
	}
	s.sessionsMu.RLock()
	n := len(s.sessions)
	s.sessionsMu.RUnlock()
	if n != 0 {
		t.Fatalf("revoked session not evicted: %d entries left", n)
	}
}

// withAuth (the gate every tool goes through) must refuse a session whose token was revoked,
// including sessions made by msngr_login, which are keyed by MCP session id only.
func TestWithAuthRefusesRevokedSession(t *testing.T) {
	s, database, agentID, plain := newRevokeTestServer(t)
	if !authed(s, plain) {
		t.Fatal("valid token should authenticate")
	}
	s.sessionsMu.RLock()
	session := s.sessions["token:"+plain]
	s.sessionsMu.RUnlock()
	if session == nil {
		t.Fatal("no cached session")
	}

	called := false
	gate := s.withAuth(func(ctx context.Context, params map[string]interface{}) *ToolResponse {
		called = true
		return &ToolResponse{OK: true}
	})
	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "msngr_list_accounts"}}

	if _, err := gate(withSession(context.Background(), session), req); err != nil || !called {
		t.Fatalf("active session should reach the handler (err=%v called=%v)", err, called)
	}

	called = false
	if err := database.RevokeAllTokensForAgent(agentID); err != nil {
		t.Fatal(err)
	}
	res, err := gate(withSession(context.Background(), session), req)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("handler ran for a revoked token")
	}
	if !res.IsError && !strings.Contains(textOf(res), "AUTHENTICATION_REQUIRED") {
		t.Fatalf("expected AUTHENTICATION_REQUIRED, got %q", textOf(res))
	}
}

func textOf(res *sdkmcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// If the token check itself fails (database unavailable), a cached session must be refused, not trusted.
func TestSessionTokenActiveFailsClosed(t *testing.T) {
	s, database, _, plain := newRevokeTestServer(t)
	if !authed(s, plain) {
		t.Fatal("valid token should authenticate")
	}
	s.sessionsMu.RLock()
	session := s.sessions["token:"+plain]
	s.sessionsMu.RUnlock()
	if !s.sessionTokenActive(session) {
		t.Fatal("active token reported inactive")
	}
	database.Close()
	if s.sessionTokenActive(session) {
		t.Fatal("token check passed although the database is closed")
	}
	if s.sessionTokenActive(nil) {
		t.Fatal("nil session reported active")
	}
}
