package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luxemque/msngr/internal/model"
)

// renderDashboard runs the dashboard handler as an authenticated operator and returns
// the rendered body.
//
// Template execution errors are logged rather than returned, so a broken template
// yields a truncated page instead of a failure. The assertions therefore check for
// content from the very end of the template.
func renderDashboard(t *testing.T, srv *Server, op *model.Operator, target string) string {
	t.Helper()

	value, err := srv.newSessionValue(op)
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
	rec := httptest.NewRecorder()

	srv.handleDashboard(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard returned status %d", rec.Code)
	}
	return rec.Body.String()
}

func TestDashboardRendersUsageSection(t *testing.T) {
	srv, op := newTestServer(t)
	body := renderDashboard(t, srv, op, "/dashboard")

	// Content from the end of the template: if execution failed partway, this is absent.
	for _, want := range []string{
		"Usage",
		"Delivery Rate",
		"Daily Volume",
		"Activity by Account",
		"Activity by Agent",
		"Archive Size",
		"</html>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard is missing %q — the template probably failed to execute", want)
		}
	}

	// The original configuration counters must survive.
	for _, want := range []string{"Mail Accounts", "Active Rules", "Queue Depth", "Pending Holds"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lost the existing counter %q", want)
		}
	}
}

// With no traffic, a delivery rate of 0% would read as "everything failed".
func TestDashboardShowsNoDeliveryRateWithoutSends(t *testing.T) {
	srv, op := newTestServer(t)
	body := renderDashboard(t, srv, op, "/dashboard")

	// Scope the check to the delivery-rate card: the generated chart CSS legitimately
	// contains "0%" as a bar height.
	card := deliveryRateCard(t, body)
	if strings.Contains(card, "%") {
		t.Errorf("delivery rate shows a figure when nothing was attempted:\n%s", card)
	}
	if !strings.Contains(card, "—") {
		t.Errorf("delivery rate does not show a placeholder:\n%s", card)
	}
	if !strings.Contains(card, "No sends attempted in this window") {
		t.Errorf("delivery rate does not explain why it is absent:\n%s", card)
	}
}

// deliveryRateCard extracts the stat card containing the delivery rate.
func deliveryRateCard(t *testing.T, body string) string {
	t.Helper()
	idx := strings.Index(body, "Delivery Rate")
	if idx < 0 {
		t.Fatal("dashboard has no Delivery Rate card")
	}
	start := strings.LastIndex(body[:idx], `<div class="stat-card">`)
	if start < 0 {
		t.Fatal("could not find the start of the Delivery Rate card")
	}
	end := strings.Index(body[idx:], "</div>\n            </div>")
	if end < 0 {
		return body[start:]
	}
	return body[start : idx+end]
}

func TestDashboardWindowSelection(t *testing.T) {
	srv, op := newTestServer(t)

	body := renderDashboard(t, srv, op, "/dashboard?days=7")
	if !strings.Contains(body, "last 7 days") {
		t.Error("?days=7 did not select the 7-day window")
	}

	// Values outside the offered set fall back to the default rather than running an
	// unbounded scan.
	body = renderDashboard(t, srv, op, "/dashboard?days=99999")
	if !strings.Contains(body, "last 30 days") {
		t.Error("an unsupported window was not clamped to the default")
	}

	body = renderDashboard(t, srv, op, "/dashboard?days=not-a-number")
	if !strings.Contains(body, "last 30 days") {
		t.Error("a non-numeric window was not clamped to the default")
	}
}

// The chart draws with CSS classes because the page CSP permits a nonced <style>
// element but not style="" attributes.
func TestDashboardChartUsesNoncedStyleNotInlineAttributes(t *testing.T) {
	srv, op := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	value, err := srv.newSessionValue(op)
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})

	// Give the request a nonce the way the security middleware does.
	rec := httptest.NewRecorder()
	handler := securityHeadersMiddleware(http.HandlerFunc(srv.handleDashboard))
	handler.ServeHTTP(rec, r)

	body := rec.Body.String()
	if !strings.Contains(body, "<style nonce=") {
		t.Error("dashboard chart styles are not in a nonced <style> element")
	}
	if strings.Contains(body, `class="usage-bar" style=`) {
		t.Error("chart bars use inline style attributes, which the CSP blocks")
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'self' 'nonce-") {
		t.Errorf("unexpected style-src policy: %q", csp)
	}
}

func TestParseUsageWindow(t *testing.T) {
	cases := map[string]int{
		"":     30,
		"7":    7,
		"30":   30,
		"90":   90,
		"1":    30,
		"365":  30,
		"-7":   30,
		"abc":  30,
		"7; 1": 30,
	}
	for input, want := range cases {
		if got := parseUsageWindow(input); got != want {
			t.Errorf("parseUsageWindow(%q) = %d, want %d", input, got, want)
		}
	}
}
