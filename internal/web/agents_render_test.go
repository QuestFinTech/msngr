package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The agents page ends with an inline script that carries the CSP nonce. A template
// field the page data does not have aborts execution at that point, so the page is
// cut off and the script never reaches the browser.
func TestAgentsPageRendersToCompletion(t *testing.T) {
	srv, op := newTestServer(t)
	value, err := srv.newSessionValue(op)
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/agents", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
	rec := httptest.NewRecorder()

	srv.handleAgents(rec, r)

	body := rec.Body.String()
	if !strings.Contains(body, "</html>") {
		t.Fatal("agents page did not render to completion")
	}
	if !strings.Contains(body, "<script nonce=\"") {
		t.Fatal("agents page script is missing")
	}
}
