package db

import "testing"

// A token counts as active only while both the token row and its agent are enabled.
func TestIsTokenActive(t *testing.T) {
	database := newTestDB(t)
	agentID, err := database.CreateAgent("Test", "test@example.invalid")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	lookup := func(plain string) int64 {
		t.Helper()
		tok, err := database.LookupAgentToken(plain)
		if err != nil || tok == nil {
			t.Fatalf("LookupAgentToken: %v %v", tok, err)
		}
		return tok.ID
	}
	active := func(id int64) bool {
		t.Helper()
		ok, err := database.IsTokenActive(id)
		if err != nil {
			t.Fatalf("IsTokenActive: %v", err)
		}
		return ok
	}

	p1, _ := database.CreateAgentToken(agentID)
	id1 := lookup(p1)
	if !active(id1) {
		t.Fatal("fresh token should be active")
	}
	if err := database.RevokeToken(id1); err != nil {
		t.Fatal(err)
	}
	if active(id1) {
		t.Fatal("revoked token should be inactive")
	}

	p2, _ := database.CreateAgentToken(agentID)
	id2 := lookup(p2)
	if err := database.RevokeAllTokensForAgent(agentID); err != nil {
		t.Fatal(err)
	}
	if active(id2) {
		t.Fatal("token should be inactive after RevokeAllTokensForAgent")
	}

	p3, _ := database.CreateAgentToken(agentID)
	id3 := lookup(p3)
	if err := database.UpdateAgentEnabled(agentID, false); err != nil {
		t.Fatal(err)
	}
	if active(id3) {
		t.Fatal("token of a disabled agent should be inactive")
	}
	if active(999999) {
		t.Fatal("unknown token id should be inactive")
	}
}
