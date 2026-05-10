// Package web provides the operator web UI and HTTP server for MSNGR.
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/luxemque/msngr/internal/audit"
	"github.com/luxemque/msngr/internal/config"
	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
	"github.com/luxemque/msngr/internal/policy"
	"github.com/luxemque/msngr/internal/storage"

	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.html
var templatesFS embed.FS

const sessionCookieName = "msngr_session"

// emailRegex validates email format.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)

// PageData holds data passed to templates.
type PageData struct {
	Title       string
	Error       string
	Success     string
	Nonce       string
	CSRFToken   string
	CurrentPage string
	Operator    *model.Operator
	IsAdmin     bool
	Data        map[string]interface{}
}

// Server handles the MSNGR web UI.
type Server struct {
	db         *db.DB
	store      *storage.Store
	audit      *audit.Logger
	templates  map[string]*template.Template
	addr       string
	server     *http.Server
	limiter    *authRateLimiter
	version                string
	hardPolicy             config.HardPolicyConfig
	operatorSessionMinutes int
	mcpHandler             http.Handler
}

// SetMCPHandler registers the MCP tool dispatch handler.
func (s *Server) SetMCPHandler(h http.Handler) {
	s.mcpHandler = h
}

// NewServer creates a new web server.
// The store parameter may be nil if filesystem storage is not configured.
func NewServer(database *db.DB, store *storage.Store, addr string, version string, hardPolicy config.HardPolicyConfig, operatorSessionMinutes int) *Server {
	if operatorSessionMinutes <= 0 {
		operatorSessionMinutes = 1440
	}
	s := &Server{
		db:                     database,
		store:                  store,
		audit:                  audit.NewLogger(database),
		addr:                   addr,
		limiter:                newAuthRateLimiter(),
		version:                version,
		hardPolicy:             hardPolicy,
		operatorSessionMinutes: operatorSessionMinutes,
	}
	s.templates = s.loadTemplates()
	return s
}

func (s *Server) loadTemplates() map[string]*template.Template {
	templates := make(map[string]*template.Template)
	pages := []string{
		"setup.html",
		"login.html",
		"dashboard.html",
		"servers.html",
		"accounts.html",
		"agents.html",
		"rules.html",
		"rules_simulate.html",
		"queue.html",
		"holds.html",
		"audit.html",
		"settings.html",
	}

	funcMap := template.FuncMap{
		"fmtInt": func(v int) string { return fmt.Sprintf("%d", v) },
		"bytesToMB": func(b int64) string {
			mb := float64(b) / (1024 * 1024)
			if mb < 0.1 {
				return fmt.Sprintf("%.2f", mb)
			}
			return fmt.Sprintf("%.1f", mb)
		},
	}

	for _, page := range pages {
		tmpl, err := template.New("").Funcs(funcMap).ParseFS(templatesFS, "templates/base.html", "templates/nav.html", "templates/"+page)
		if err != nil {
			panic(fmt.Sprintf("parse template %s: %v", page, err))
		}
		templates[page] = tmpl
	}
	return templates
}

// Start starts the HTTP server (blocking).
func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/health", s.handleHealth)

	// MCP endpoint (no web auth — uses Bearer token)
	if s.mcpHandler != nil {
		mux.Handle("/mcp", s.mcpHandler)
	}
	mux.HandleFunc("/setup", s.handleSetup)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/dashboard", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/servers", s.requireAuth(s.handleServers))
	mux.HandleFunc("/accounts", s.requireAuth(s.handleAccounts))
	mux.HandleFunc("/agents", s.requireAuth(s.handleAgents))
	mux.HandleFunc("/rules", s.requireAuth(s.handleRules))
	mux.HandleFunc("/rules/export", s.requireAuth(s.handleRulesExport))
	mux.HandleFunc("/rules/import", s.requireAuth(s.handleRulesImport))
	mux.HandleFunc("/rules/simulate", s.requireAuth(s.handleRulesSimulate))
	mux.HandleFunc("/queue", s.requireAuth(s.handleQueue))
	mux.HandleFunc("/holds", s.requireAuth(s.handleHolds))
	mux.HandleFunc("/audit", s.requireAuth(s.handleAudit))
	mux.HandleFunc("/settings", s.requireAuth(s.handleSettings))

	s.server = &http.Server{
		Addr:           s.addr,
		Handler:        securityHeadersMiddleware(maxBytesMiddleware(mux)),
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// --- Middleware ---

type contextKey string

const nonceKey contextKey = "csp-nonce"

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func getNonce(r *http.Request) string {
	if v, ok := r.Context().Value(nonceKey).(string); ok {
		return v
	}
	return ""
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := generateNonce()
		ctx := context.WithValue(r.Context(), nonceKey, nonce)
		r = r.WithContext(ctx)

		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'nonce-"+nonce+"'; "+
				"style-src 'self' 'nonce-"+nonce+"'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"object-src 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Embedder-Policy", "credentialless")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

func maxBytesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

// --- Auth ---

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op := s.currentOperator(r)
		if op == nil {
			// If no operators exist yet, redirect to initial setup instead of login.
			count, _ := s.db.CountOperators()
			if count == 0 {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) currentOperator(r *http.Request) *model.Operator {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	// Session value is "id:email" signed simply with existence in DB.
	parts := strings.SplitN(c.Value, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	var id int64
	if _, err := fmt.Sscanf(parts[0], "%d", &id); err != nil {
		return nil
	}
	op, err := s.db.GetOperatorByID(id)
	if err != nil || op == nil {
		return nil
	}
	if op.Email != parts[1] {
		return nil
	}
	return op
}

func (s *Server) setSession(w http.ResponseWriter, op *model.Operator) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    fmt.Sprintf("%d:%s", op.ID, op.Email),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   s.operatorSessionMinutes * 60,
	})
}

func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// --- Rate limiter ---

type authRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*authRateEntry
}

type authRateEntry struct {
	attempts []time.Time
}

func newAuthRateLimiter() *authRateLimiter {
	rl := &authRateLimiter{entries: make(map[string]*authRateEntry)}
	go rl.cleanup()
	return rl
}

func (rl *authRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UTC()
	cutoff := now.Add(-60 * time.Second)

	entry, ok := rl.entries[ip]
	if !ok {
		entry = &authRateEntry{}
		rl.entries[ip] = entry
	}

	valid := entry.attempts[:0]
	for _, t := range entry.attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	entry.attempts = valid

	if len(entry.attempts) >= 5 {
		return false
	}
	entry.attempts = append(entry.attempts, now)
	return true
}

func (rl *authRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().UTC().Add(-2 * time.Minute)
		for ip, entry := range rl.entries {
			if len(entry.attempts) == 0 || entry.attempts[len(entry.attempts)-1].Before(cutoff) {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func extractClientIP(r *http.Request) string {
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- Render helper ---

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, pd *PageData) {
	tmpl, ok := s.templates[page]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}

	pd.Nonce = getNonce(r)
	pd.CSRFToken = ensureCSRFToken(w, r)

	if pd.Operator == nil {
		pd.Operator = s.currentOperator(r)
	}
	if pd.Operator != nil {
		pd.IsAdmin = pd.Operator.Role == "master_admin" || pd.Operator.Role == "admin"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base", pd); err != nil {
		slog.Error("render template", "page", page, "error", err)
	}
}

// --- Password validation ---

func validatePassword(password string) string {
	if len(password) < 12 {
		return "Password must be at least 12 characters."
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return "Password must contain an uppercase letter."
	}
	if !hasLower {
		return "Password must contain a lowercase letter."
	}
	if !hasDigit {
		return "Password must contain a digit."
	}
	if !hasSpecial {
		return "Password must contain a special character."
	}
	return ""
}

// --- Handlers ---

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	count, _ := s.db.CountOperators()
	if count == 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if s.currentOperator(r) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	count, _ := s.db.CountOperators()
	if count > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	pd := &PageData{Title: "Setup", CurrentPage: "setup"}

	if r.Method == http.MethodGet {
		s.render(w, r, "setup.html", pd)
		return
	}

	// POST: create master admin
	if !validateCSRF(r) {
		pd.Error = "Invalid request. Please try again."
		s.render(w, r, "setup.html", pd)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	// Preserve form values
	pd.Data = map[string]interface{}{
		"Name":  name,
		"Email": email,
	}

	if name == "" || email == "" || password == "" {
		pd.Error = "All fields are required."
		s.render(w, r, "setup.html", pd)
		return
	}

	if !emailRegex.MatchString(email) {
		pd.Error = "Please enter a valid email address."
		s.render(w, r, "setup.html", pd)
		return
	}

	if password != confirmPassword {
		pd.Error = "Passwords do not match."
		s.render(w, r, "setup.html", pd)
		return
	}

	if msg := validatePassword(password); msg != "" {
		pd.Error = msg
		s.render(w, r, "setup.html", pd)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		pd.Error = "Internal error. Please try again."
		s.render(w, r, "setup.html", pd)
		return
	}

	_, err = s.db.CreateOperator(name, email, string(hash), "master_admin")
	if err != nil {
		pd.Error = "Could not create admin account: " + err.Error()
		s.render(w, r, "setup.html", pd)
		return
	}

	_ = s.db.SetSystemSetting("setup_completed", "true")
	slog.Info("Master admin created", "name", name, "email", email)

	http.Redirect(w, r, "/login?setup=ok", http.StatusSeeOther)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// If no operators exist, redirect to setup.
	count, _ := s.db.CountOperators()
	if count == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	// If already logged in, go to dashboard.
	if s.currentOperator(r) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	pd := &PageData{Title: "Sign In", CurrentPage: "login"}

	if r.URL.Query().Get("setup") == "ok" {
		pd.Success = "Admin account created. Please sign in."
	}

	if r.Method == http.MethodGet {
		s.render(w, r, "login.html", pd)
		return
	}

	// POST: authenticate
	if !validateCSRF(r) {
		pd.Error = "Invalid request. Please try again."
		s.render(w, r, "login.html", pd)
		return
	}

	ip := extractClientIP(r)
	if !s.limiter.allow(ip) {
		pd.Error = "Too many attempts. Please wait a moment."
		s.render(w, r, "login.html", pd)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	op, err := s.db.GetOperatorByEmail(email)
	if err != nil || op == nil {
		pd.Error = "Invalid email or password."
		s.render(w, r, "login.html", pd)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(password)); err != nil {
		pd.Error = "Invalid email or password."
		s.render(w, r, "login.html", pd)
		return
	}

	_ = s.db.UpdateOperatorLogin(op.ID)
	_ = s.audit.LogOperatorLogin(r.Context(), fmt.Sprintf("%d", op.ID), op.Email)
	s.setSession(w, op)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetDashboardStats()
	if err != nil {
		slog.Error("dashboard stats", "error", err)
		stats = &db.DashboardStats{}
	}

	// Show welcome message only on the very first dashboard visit.
	showWelcome := false
	val, _ := s.db.GetSystemSetting("welcome_dismissed")
	if val == "" {
		showWelcome = true
		_ = s.db.SetSystemSetting("welcome_dismissed", "true")
	}

	pd := &PageData{
		Title:       "Dashboard",
		CurrentPage: "dashboard",
		Data: map[string]interface{}{
			"Stats":       stats,
			"ShowWelcome": showWelcome,
		},
	}
	s.render(w, r, "dashboard.html", pd)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type healthResponse struct {
		Status            string `json:"status"`
		DB                string `json:"db"`
		Accounts          int    `json:"accounts"`
		UnhealthyAccounts int    `json:"unhealthy_accounts"`
		QueueDepth        int    `json:"queue_depth"`
		PendingHolds      int    `json:"pending_holds"`
		Version           string `json:"version"`
	}

	resp := healthResponse{
		Status:  "ok",
		DB:      "ok",
		Version: s.version,
	}

	// Check database connectivity.
	if err := s.db.Ping(); err != nil {
		resp.Status = "degraded"
		resp.DB = "unreachable"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Get dashboard stats for counts.
	stats, err := s.db.GetDashboardStats()
	if err != nil {
		slog.Error("health check stats", "error", err)
		resp.Status = "degraded"
	} else {
		resp.Accounts = stats.Accounts
		resp.QueueDepth = stats.QueueDepth
		resp.PendingHolds = stats.PendingHolds
	}

	// Check unhealthy accounts.
	unhealthy, err := s.db.GetUnhealthyAccountCount()
	if err != nil {
		slog.Error("health check unhealthy accounts", "error", err)
	} else {
		resp.UnhealthyAccounts = unhealthy
		if unhealthy > 0 {
			resp.Status = "degraded"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if resp.Status != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

// --- Operator UI Page Handlers ---

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Mail Servers",
		CurrentPage: "servers",
		Data:        map[string]interface{}{},
	}

	if r.Method == http.MethodPost {
		if !validateCSRF(r) {
			pd.Error = "Invalid request. Please try again."
		} else {
			action := r.FormValue("action")
			switch action {
			case "test":
				serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
				if serverID == 0 {
					pd.Error = "Server not found."
				} else {
					pd.Success = s.testServerConnectivity(serverID)
					if pd.Success == "" {
						pd.Error = "Server not found."
					}
				}
			case "edit":
				serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
				imapPort, _ := strconv.Atoi(r.FormValue("imap_port"))
				smtpPort, _ := strconv.Atoi(r.FormValue("smtp_port"))
				ms := &model.MailServer{
					ID:       serverID,
					Name:     strings.TrimSpace(r.FormValue("name")),
					IMAPHost: strings.TrimSpace(r.FormValue("imap_host")),
					IMAPPort: imapPort,
					IMAPTLS:  r.FormValue("imap_tls") == "1",
					SMTPHost: strings.TrimSpace(r.FormValue("smtp_host")),
					SMTPPort: smtpPort,
					SMTPTLS:  r.FormValue("smtp_tls") == "1",
				}
				if ms.Name == "" || ms.IMAPHost == "" || ms.SMTPHost == "" {
					pd.Error = "Name, IMAP host, and SMTP host are required."
				} else if err := s.db.UpdateMailServer(ms); err != nil {
					pd.Error = "Could not update server: " + err.Error()
				} else {
					pd.Success = "Mail server updated successfully."
				}
			case "delete":
				serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
				count, _ := s.db.CountAccountsForServer(serverID)
				if count > 0 {
					pd.Error = fmt.Sprintf("Cannot delete server: %d account(s) still reference it.", count)
				} else if err := s.db.DeleteMailServer(serverID); err != nil {
					pd.Error = "Could not delete server: " + err.Error()
				} else {
					pd.Success = "Mail server deleted."
				}
			default:
				imapPort, _ := strconv.Atoi(r.FormValue("imap_port"))
				smtpPort, _ := strconv.Atoi(r.FormValue("smtp_port"))
				ms := &model.MailServer{
					Name:     strings.TrimSpace(r.FormValue("name")),
					IMAPHost: strings.TrimSpace(r.FormValue("imap_host")),
					IMAPPort: imapPort,
					IMAPTLS:  r.FormValue("imap_tls") == "1",
					SMTPHost: strings.TrimSpace(r.FormValue("smtp_host")),
					SMTPPort: smtpPort,
					SMTPTLS:  r.FormValue("smtp_tls") == "1",
				}
				if ms.Name == "" || ms.IMAPHost == "" || ms.SMTPHost == "" {
					pd.Error = "Name, IMAP host, and SMTP host are required."
				} else {
					_, err := s.db.CreateMailServer(ms)
					if err != nil {
						pd.Error = "Could not create server: " + err.Error()
					} else {
						pd.Success = "Mail server created successfully."
					}
				}
			}
		}
	}

	servers, err := s.db.ListMailServers()
	if err != nil {
		slog.Error("list mail servers", "error", err)
	}
	pd.Data["Servers"] = servers

	// Build account counts map.
	accountCounts := make(map[int64]int)
	for _, srv := range servers {
		count, err := s.db.CountAccountsForServer(srv.ID)
		if err != nil {
			slog.Error("count accounts for server", "server_id", srv.ID, "error", err)
		}
		accountCounts[srv.ID] = count
	}
	pd.Data["AccountCounts"] = accountCounts

	// Load server for editing if ?edit=ID is present.
	if editID := r.URL.Query().Get("edit"); editID != "" {
		id, _ := strconv.ParseInt(editID, 10, 64)
		if id > 0 {
			srv, err := s.db.GetMailServerByID(id)
			if err != nil {
				slog.Error("load server for edit", "error", err)
			} else if srv != nil {
				pd.Data["EditServer"] = srv
			}
		}
	}

	s.render(w, r, "servers.html", pd)
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Mail Accounts",
		CurrentPage: "accounts",
		Data:        map[string]interface{}{},
	}

	if r.Method == http.MethodPost {
		if !validateCSRF(r) {
			pd.Error = "Invalid request. Please try again."
		} else {
			action := r.FormValue("action")
			switch action {
			case "test":
				serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
				if serverID == 0 {
					pd.Error = "Please select a mail server to test."
				} else {
					pd.Success = s.testServerConnectivity(serverID)
					if pd.Success == "" {
						pd.Error = "Mail server not found."
					}
				}
			case "test_account":
				accountID, _ := strconv.ParseInt(r.FormValue("account_id"), 10, 64)
				acct, err := s.db.GetAccountByID(accountID)
				if err != nil || acct == nil {
					pd.Error = "Account not found."
				} else if acct.ServerID == 0 {
					pd.Error = "Account has no server configured."
				} else {
					result := s.testServerConnectivity(acct.ServerID)
					if result == "" {
						pd.Error = "Mail server not found."
					} else {
						pd.Success = result
						// Update health status based on test result.
						if strings.Contains(result, "FAILED") {
							_ = s.db.UpdateAccountHealth(accountID, "error")
						} else {
							_ = s.db.UpdateAccountHealth(accountID, "ok")
						}
					}
				}
			case "edit":
				accountID, _ := strconv.ParseInt(r.FormValue("account_id"), 10, 64)
				serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
				emailAddr := strings.TrimSpace(r.FormValue("email_address"))
				a := &model.Account{
					ID:                   accountID,
					Name:                 emailAddr,
					EmailAddress:         emailAddr,
					ServerID:             serverID,
					RetrievalEnabled:     r.FormValue("retrieval_enabled") == "1",
					SendingEnabled:       r.FormValue("sending_enabled") == "1",
					DeleteAfterRetrieval: r.FormValue("delete_after_retrieval") == "1",
					StorageMode:          r.FormValue("storage_mode"),
					Enabled:              r.FormValue("enabled") == "1",
				}
				if a.EmailAddress == "" {
					pd.Error = "Email address is required."
				} else if err := s.db.UpdateAccount(a); err != nil {
					pd.Error = "Could not update account: " + err.Error()
				} else {
					// Update credentials if provided.
					smtpUser := strings.TrimSpace(r.FormValue("smtp_username"))
					smtpPass := r.FormValue("smtp_password")
					if smtpUser != "" || smtpPass != "" {
						_ = s.db.SaveAccountCredentials(accountID, smtpUser, smtpPass)
					}
					pd.Success = "Account updated successfully."
				}
			case "delete":
				accountID, _ := strconv.ParseInt(r.FormValue("account_id"), 10, 64)
				if err := s.db.DeleteAccount(accountID); err != nil {
					pd.Error = "Could not delete account: " + err.Error()
				} else {
					pd.Success = "Account deleted."
				}
			default:
				serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
				emailAddr := strings.TrimSpace(r.FormValue("email_address"))
				a := &model.Account{
					Name:                 emailAddr,
					EmailAddress:         emailAddr,
					ServerID:             serverID,
					RetrievalEnabled:     r.FormValue("retrieval_enabled") == "1",
					SendingEnabled:       r.FormValue("sending_enabled") == "1",
					DeleteAfterRetrieval: r.FormValue("delete_after_retrieval") == "1",
					StorageMode:          r.FormValue("storage_mode"),
				}
				if a.EmailAddress == "" {
					pd.Error = "Email address is required."
				} else {
					accountID, err := s.db.CreateAccount(a)
					if err != nil {
						pd.Error = "Could not create account: " + err.Error()
					} else {
						smtpUser := strings.TrimSpace(r.FormValue("smtp_username"))
						smtpPass := r.FormValue("smtp_password")
						if smtpUser != "" || smtpPass != "" {
							_ = s.db.SaveAccountCredentials(accountID, smtpUser, smtpPass)
						}
						pd.Success = "Account created successfully."
					}
				}
			}
		}
	}

	accounts, err := s.db.ListAccounts()
	if err != nil {
		slog.Error("list accounts", "error", err)
	}
	pd.Data["Accounts"] = accounts

	servers, err := s.db.ListMailServers()
	if err != nil {
		slog.Error("list mail servers for accounts page", "error", err)
	}
	pd.Data["Servers"] = servers

	// Load account for editing if ?edit=ID is present.
	if editID := r.URL.Query().Get("edit"); editID != "" {
		id, _ := strconv.ParseInt(editID, 10, 64)
		if id > 0 {
			acct, err := s.db.GetAccountByID(id)
			if err != nil {
				slog.Error("load account for edit", "error", err)
			} else if acct != nil {
				pd.Data["EditAccount"] = acct
			}
		}
	}

	s.render(w, r, "accounts.html", pd)
}

// testServerConnectivity tests TCP connectivity to a mail server's IMAP and SMTP ports.
// Returns a success message string, or "" if the server was not found.
func (s *Server) testServerConnectivity(serverID int64) string {
	srv, err := s.db.GetMailServerByID(serverID)
	if err != nil || srv == nil {
		return ""
	}
	var results []string
	if srv.IMAPHost != "" {
		addr := net.JoinHostPort(srv.IMAPHost, fmt.Sprintf("%d", srv.IMAPPort))
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			results = append(results, fmt.Sprintf("IMAP %s: FAILED — %s", addr, err.Error()))
		} else {
			conn.Close()
			results = append(results, fmt.Sprintf("IMAP %s: OK", addr))
		}
	}
	if srv.SMTPHost != "" {
		addr := net.JoinHostPort(srv.SMTPHost, fmt.Sprintf("%d", srv.SMTPPort))
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			results = append(results, fmt.Sprintf("SMTP %s: FAILED — %s", addr, err.Error()))
		} else {
			conn.Close()
			results = append(results, fmt.Sprintf("SMTP %s: OK", addr))
		}
	}
	if len(results) == 0 {
		return "No IMAP or SMTP host configured on this server."
	}
	return "Connectivity test: " + strings.Join(results, " · ")
}

// defaultAgentCapabilities is the trio auto-granted on agent creation when the
// agent's email matches an existing account, and the only set accepted by
// grant_permission. Revocation accepts arbitrary strings so operators can
// remove non-standard rows that may have been inserted directly.
var defaultAgentCapabilities = []string{"send", "read", "download_attachment"}

func isKnownCapability(c string) bool {
	for _, k := range defaultAgentCapabilities {
		if k == c {
			return true
		}
	}
	return false
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Agents",
		CurrentPage: "agents",
		Data:        map[string]interface{}{},
	}

	if r.Method == http.MethodPost {
		if !validateCSRF(r) {
			pd.Error = "Invalid request. Please try again."
		} else {
			action := r.FormValue("action")
			switch action {
			case "renew_token":
				agentID, err := strconv.ParseInt(r.FormValue("agent_id"), 10, 64)
				if err != nil {
					pd.Error = "Invalid agent."
				} else {
					// Revoke all existing tokens, then create a new one.
					_ = s.db.RevokeAllTokensForAgent(agentID)
					plaintext, err := s.db.CreateAgentToken(agentID)
					if err != nil {
						pd.Error = "Could not create token: " + err.Error()
					} else {
						pd.Success = "New token generated. Copy it now — it will not be shown again."
						pd.Data["NewToken"] = plaintext
						pd.Data["NewTokenAgentID"] = agentID
					}
				}
			case "enable_agent":
				agentID, _ := strconv.ParseInt(r.FormValue("agent_id"), 10, 64)
				if err := s.db.UpdateAgentEnabled(agentID, true); err != nil {
					pd.Error = "Could not enable agent: " + err.Error()
				} else {
					http.Redirect(w, r, "/agents", http.StatusSeeOther)
					return
				}
			case "disable_agent":
				agentID, _ := strconv.ParseInt(r.FormValue("agent_id"), 10, 64)
				if err := s.db.UpdateAgentEnabled(agentID, false); err != nil {
					pd.Error = "Could not disable agent: " + err.Error()
				} else {
					http.Redirect(w, r, "/agents", http.StatusSeeOther)
					return
				}
			case "grant_permission":
				agentID, errA := strconv.ParseInt(r.FormValue("agent_id"), 10, 64)
				accountID, errB := strconv.ParseInt(r.FormValue("account_id"), 10, 64)
				capability := strings.TrimSpace(r.FormValue("capability"))
				if errA != nil || errB != nil || !isKnownCapability(capability) {
					pd.Error = "Invalid grant request."
				} else if err := s.db.GrantAgentPermission(agentID, accountID, capability); err != nil {
					pd.Error = "Could not grant permission: " + err.Error()
				} else {
					http.Redirect(w, r, "/agents", http.StatusSeeOther)
					return
				}
			case "revoke_permission":
				agentID, errA := strconv.ParseInt(r.FormValue("agent_id"), 10, 64)
				accountID, errB := strconv.ParseInt(r.FormValue("account_id"), 10, 64)
				capability := strings.TrimSpace(r.FormValue("capability"))
				if errA != nil || errB != nil || capability == "" {
					pd.Error = "Invalid revoke request."
				} else if err := s.db.RevokeAgentPermission(agentID, accountID, capability); err != nil {
					pd.Error = "Could not revoke permission: " + err.Error()
				} else {
					http.Redirect(w, r, "/agents", http.StatusSeeOther)
					return
				}
			default:
				// create_agent + auto-create token + auto-grant default capabilities
				// when the agent's email matches an existing account.
				displayName := strings.TrimSpace(r.FormValue("display_name"))
				agentEmail := strings.TrimSpace(r.FormValue("agent_email"))
				if displayName == "" || agentEmail == "" {
					pd.Error = "Name and agent email are required."
				} else {
					agentID, err := s.db.CreateAgent(displayName, agentEmail)
					if err != nil {
						pd.Error = "Could not create agent: " + err.Error()
					} else {
						plaintext, err := s.db.CreateAgentToken(agentID)
						if err != nil {
							pd.Error = "Agent created but token generation failed: " + err.Error()
						} else {
							pd.Success = "Agent created. Copy the API token now — it will not be shown again."
							pd.Data["NewToken"] = plaintext
							pd.Data["NewTokenAgentID"] = agentID
							// Auto-grant the default trio if a matching account exists.
							// Failures here log a warning but do not break agent creation —
							// the operator can still grant manually from the UI.
							if acct, lookupErr := s.db.GetAccountByEmail(agentEmail); lookupErr != nil {
								slog.Warn("auto-grant: lookup account by email failed", "agent_id", agentID, "error", lookupErr)
							} else if acct != nil {
								granted := 0
								for _, cap := range defaultAgentCapabilities {
									if grantErr := s.db.GrantAgentPermission(agentID, acct.ID, cap); grantErr != nil {
										slog.Warn("auto-grant: grant failed", "agent_id", agentID, "account_id", acct.ID, "capability", cap, "error", grantErr)
									} else {
										granted++
									}
								}
								slog.Info("auto-granted default capabilities", "agent_id", agentID, "account_id", acct.ID, "granted", granted)
							}
						}
					}
				}
			}
		}
	}

	agents, err := s.db.ListAgents()
	if err != nil {
		slog.Error("list agents", "error", err)
	}
	pd.Data["Agents"] = agents

	// Build token status map: agent ID -> active token info.
	tokenMap := make(map[int64]*model.AgentToken)
	for _, a := range agents {
		tok, err := s.db.GetActiveTokenForAgent(a.ID)
		if err != nil {
			slog.Error("get active token", "error", err, "agent_id", a.ID)
		}
		if tok != nil {
			tokenMap[a.ID] = tok
		}
	}
	pd.Data["TokenMap"] = tokenMap

	accounts, err := s.db.ListAccounts()
	if err != nil {
		slog.Error("list accounts for agent emails", "error", err)
	}
	pd.Data["Accounts"] = accounts

	// Build permissions map (agent_id -> []AgentPermission) and an
	// account-email-by-id lookup so the template can render grant/revoke rows
	// without re-walking the accounts slice on every iteration.
	permissionsByAgent := make(map[int64][]model.AgentPermission, len(agents))
	for _, a := range agents {
		perms, err := s.db.ListAgentPermissions(a.ID)
		if err != nil {
			slog.Error("list agent permissions", "error", err, "agent_id", a.ID)
			continue
		}
		permissionsByAgent[a.ID] = perms
	}
	pd.Data["PermissionsByAgent"] = permissionsByAgent

	accountEmailByID := make(map[int64]string, len(accounts))
	for _, ac := range accounts {
		accountEmailByID[ac.ID] = ac.EmailAddress
	}
	pd.Data["AccountEmailByID"] = accountEmailByID
	pd.Data["DefaultCapabilities"] = defaultAgentCapabilities

	s.render(w, r, "agents.html", pd)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Policy Rules",
		CurrentPage: "rules",
		Data:        map[string]interface{}{},
	}

	if msg := r.URL.Query().Get("success"); msg != "" {
		pd.Success = msg
	}
	if msg := r.URL.Query().Get("error"); msg != "" {
		pd.Error = msg
	}

	if r.Method == http.MethodPost {
		if !validateCSRF(r) {
			pd.Error = "Invalid request. Please try again."
		} else {
			action := r.FormValue("action")
			switch action {
			case "enable_rule":
				ruleID, _ := strconv.ParseInt(r.FormValue("rule_id"), 10, 64)
				if err := s.db.UpdateRuleEnabled(ruleID, true); err != nil {
					pd.Error = "Could not enable rule: " + err.Error()
				} else {
					http.Redirect(w, r, "/rules", http.StatusSeeOther)
					return
				}
			case "disable_rule":
				ruleID, _ := strconv.ParseInt(r.FormValue("rule_id"), 10, 64)
				if err := s.db.UpdateRuleEnabled(ruleID, false); err != nil {
					pd.Error = "Could not disable rule: " + err.Error()
				} else {
					http.Redirect(w, r, "/rules", http.StatusSeeOther)
					return
				}
			case "delete_rule":
				ruleID, _ := strconv.ParseInt(r.FormValue("rule_id"), 10, 64)
				if err := s.db.DeleteRule(ruleID); err != nil {
					pd.Error = "Could not delete rule: " + err.Error()
				} else {
					http.Redirect(w, r, "/rules", http.StatusSeeOther)
					return
				}
			case "edit_rule":
				ruleID, _ := strconv.ParseInt(r.FormValue("rule_id"), 10, 64)
				priority, _ := strconv.Atoi(r.FormValue("priority"))
				rule := &model.Rule{
					ID:            ruleID,
					Name:          strings.TrimSpace(r.FormValue("name")),
					Priority:      priority,
					Layer:         r.FormValue("layer"),
					Scope:         "global",
					MatchCriteria: strings.TrimSpace(r.FormValue("match_criteria")),
					Action:        r.FormValue("rule_action"),
					Explanation:   strings.TrimSpace(r.FormValue("explanation")),
				}
				if rule.Name == "" || rule.MatchCriteria == "" {
					pd.Error = "Name and match criteria are required."
				} else if err := s.db.UpdateRule(rule); err != nil {
					pd.Error = "Could not update rule: " + err.Error()
				} else {
					pd.Success = "Rule updated."
				}
			default:
				// create rule
				priority, _ := strconv.Atoi(r.FormValue("priority"))
				rule := &model.Rule{
					Name:          strings.TrimSpace(r.FormValue("name")),
					Priority:      priority,
					Layer:         r.FormValue("layer"),
					Scope:         "global",
					MatchCriteria: strings.TrimSpace(r.FormValue("match_criteria")),
					Action:        r.FormValue("rule_action"),
					Explanation:   strings.TrimSpace(r.FormValue("explanation")),
				}
				if rule.Name == "" || rule.MatchCriteria == "" {
					pd.Error = "Name and match criteria are required."
				} else {
					_, err := s.db.CreateRule(rule)
					if err != nil {
						pd.Error = "Could not create rule: " + err.Error()
					} else {
						pd.Success = "Rule created successfully."
					}
				}
			}
		}
	}

	// Load rule for editing if ?edit=ID is present.
	if editID := r.URL.Query().Get("edit"); editID != "" {
		id, _ := strconv.ParseInt(editID, 10, 64)
		if id > 0 {
			editRule, err := s.db.GetRuleByID(id)
			if err != nil {
				slog.Error("load rule for edit", "error", err)
			} else if editRule != nil {
				pd.Data["EditRule"] = editRule
			}
		}
	}

	rules, err := s.db.ListRules()
	if err != nil {
		slog.Error("list rules", "error", err)
	}
	pd.Data["Rules"] = rules
	pd.Data["HardPolicy"] = s.hardPolicy

	accounts, err := s.db.ListAccounts()
	if err != nil {
		slog.Error("list accounts for rules page", "error", err)
	}
	pd.Data["Accounts"] = accounts

	s.render(w, r, "rules.html", pd)
}

func (s *Server) handleRulesSimulate(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Simulate",
		CurrentPage: "rules_simulate",
		Data:        map[string]interface{}{},
	}

	accounts, err := s.db.ListAccounts()
	if err != nil {
		slog.Error("list accounts for simulation", "error", err)
	}
	pd.Data["Accounts"] = accounts

	if r.Method == http.MethodPost {
		if !validateCSRF(r) {
			pd.Error = "Invalid request. Please try again."
		} else {
			agentName := strings.TrimSpace(r.FormValue("agent_name"))
			accountIDStr := r.FormValue("account_id")
			accountID, _ := strconv.ParseInt(accountIDStr, 10, 64)
			messageSize, _ := strconv.ParseInt(r.FormValue("message_size"), 10, 64)
			recipient := strings.TrimSpace(r.FormValue("recipient"))
			subject := strings.TrimSpace(r.FormValue("subject"))
			bodyText := strings.TrimSpace(r.FormValue("body_text"))
			attachmentFilename := strings.TrimSpace(r.FormValue("attachment_filename"))

			// Preserve form values for re-display
			pd.Data["SimAgentName"] = agentName
			pd.Data["SimAccountID"] = accountIDStr
			pd.Data["SimRecipient"] = recipient
			pd.Data["SimSubject"] = subject
			pd.Data["SimBody"] = bodyText
			pd.Data["SimSize"] = fmt.Sprintf("%d", messageSize)
			pd.Data["SimAttachment"] = attachmentFilename

			// Resolve agent name to numeric ID for permission checks.
			var agentNumericID int64
			if agentName != "" {
				if agent, err := s.db.GetAgentByName(agentName); err == nil && agent != nil {
					agentNumericID = agent.ID
				}
			}

			action := policy.Action{
				Type:           r.FormValue("action_type"),
				AgentName:      agentName,
				AgentNumericID: agentNumericID,
				AccountID:      accountID,
				Subject:        subject,
				BodyText:       bodyText,
				MessageSize:    messageSize,
			}

			if recipient != "" {
				action.ToAddrs = []string{recipient}
			}
			if attachmentFilename != "" {
				action.Attachments = []policy.AttachmentInfo{
					{Filename: attachmentFilename},
				}
			}

			engine := policy.NewEngine(s.db, s.hardPolicy)
			decision, err := engine.Evaluate(r.Context(), action)
			if err != nil {
				pd.Error = "Simulation error: " + err.Error()
			} else {
				pd.Data["SimResult"] = decision
			}
		}
	}

	s.render(w, r, "rules_simulate.html", pd)
}

// --- Rule Export/Import ---

// RuleExport is the per-rule structure for export files.
type RuleExport struct {
	Name          string      `json:"name"`
	Priority      int         `json:"priority"`
	Layer         string      `json:"layer"`
	Scope         string      `json:"scope"`
	Action        string      `json:"action"`
	MatchCriteria interface{} `json:"match_criteria"`
	Explanation   string      `json:"explanation"`
	Enabled       bool        `json:"enabled"`
}

// RulesExportFile is the top-level structure for exported rule files.
type RulesExportFile struct {
	MSNGRVersion string       `json:"msngr_version"`
	ExportedAt   string       `json:"exported_at"`
	Rules        []RuleExport `json:"rules"`
}

func (s *Server) handleRulesExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rules, err := s.db.ListRules()
	if err != nil {
		http.Error(w, "failed to load rules", http.StatusInternalServerError)
		return
	}

	exports := make([]RuleExport, 0, len(rules))
	for _, rule := range rules {
		var mc interface{}
		if err := json.Unmarshal([]byte(rule.MatchCriteria), &mc); err != nil {
			// Fall back to the raw string if it is not valid JSON.
			mc = rule.MatchCriteria
		}
		exports = append(exports, RuleExport{
			Name:          rule.Name,
			Priority:      rule.Priority,
			Layer:         rule.Layer,
			Scope:         rule.Scope,
			Action:        rule.Action,
			MatchCriteria: mc,
			Explanation:   rule.Explanation,
			Enabled:       rule.Enabled,
		})
	}

	out := RulesExportFile{
		MSNGRVersion: s.version,
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		Rules:        exports,
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		http.Error(w, "failed to marshal rules", http.StatusInternalServerError)
		return
	}

	filename := "msngr-rules-" + time.Now().UTC().Format("2006-01-02") + ".json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Write(data)
}

func (s *Server) handleRulesImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !validateCSRF(r) {
		http.Redirect(w, r, "/rules?error=Invalid+request.+Please+try+again.", http.StatusSeeOther)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Redirect(w, r, "/rules?error=Could+not+parse+upload:+"+err.Error(), http.StatusSeeOther)
		return
	}

	file, _, err := r.FormFile("rules_file")
	if err != nil {
		http.Redirect(w, r, "/rules?error=No+file+uploaded.", http.StatusSeeOther)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, "/rules?error=Could+not+read+file.", http.StatusSeeOther)
		return
	}

	var exportFile RulesExportFile
	if err := json.Unmarshal(data, &exportFile); err != nil {
		http.Redirect(w, r, "/rules?error=Invalid+JSON+format.", http.StatusSeeOther)
		return
	}

	mode := r.FormValue("mode") // "overwrite" or "skip"

	imported := 0
	skipped := 0
	var importErrors []string
	for i, re := range exportFile.Rules {
		if re.Name == "" {
			importErrors = append(importErrors, fmt.Sprintf("rule %d: name is required", i+1))
			continue
		}
		if re.Action != "allow" && re.Action != "deny" && re.Action != "hold" {
			importErrors = append(importErrors, fmt.Sprintf("rule %d (%s): action must be allow, deny, or hold", i+1, re.Name))
			continue
		}
		if re.Layer != "B" && re.Layer != "C" && re.Layer != "D" {
			importErrors = append(importErrors, fmt.Sprintf("rule %d (%s): layer must be B, C, or D", i+1, re.Name))
			continue
		}

		mcBytes, err := json.Marshal(re.MatchCriteria)
		if err != nil {
			importErrors = append(importErrors, fmt.Sprintf("rule %d (%s): invalid match_criteria", i+1, re.Name))
			continue
		}

		rule := &model.Rule{
			Name:          re.Name,
			Priority:      re.Priority,
			Layer:         re.Layer,
			Scope:         re.Scope,
			MatchCriteria: string(mcBytes),
			Action:        re.Action,
			Explanation:   re.Explanation,
		}
		ok, err := s.db.ImportRule(rule, mode)
		if err != nil {
			importErrors = append(importErrors, fmt.Sprintf("rule %d (%s): %v", i+1, re.Name, err))
			continue
		}
		if ok {
			imported++
		} else {
			skipped++
		}
	}

	if len(importErrors) > 0 {
		msg := fmt.Sprintf("Imported %d rules with %d errors: %s", imported, len(importErrors), strings.Join(importErrors, "; "))
		http.Redirect(w, r, "/rules?error="+msg, http.StatusSeeOther)
		return
	}

	msg := fmt.Sprintf("Imported %d rules", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(", %d skipped (duplicates)", skipped)
	}
	msg += "."
	http.Redirect(w, r, "/rules?success="+msg, http.StatusSeeOther)
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Outbound Queue",
		CurrentPage: "queue",
		Data:        map[string]interface{}{},
	}

	if r.Method == http.MethodPost {
		if !validateCSRF(r) {
			pd.Error = "Invalid request. Please try again."
		} else if r.FormValue("action") == "cancel" {
			id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
			if err != nil {
				pd.Error = "Invalid queue item ID."
			} else {
				if err := s.db.UpdateQueueStatus(id, "cancelled"); err != nil {
					pd.Error = "Could not cancel item: " + err.Error()
				} else {
					pd.Success = "Queue item cancelled."
				}
			}
		}
	}

	statusFilter := r.URL.Query().Get("status")
	pd.Data["StatusFilter"] = statusFilter

	items, err := s.db.ListQueueItems(statusFilter, 200)
	if err != nil {
		slog.Error("list queue items", "error", err)
	}
	pd.Data["Items"] = items

	s.render(w, r, "queue.html", pd)
}

func (s *Server) handleHolds(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Held Messages",
		CurrentPage: "holds",
		Data:        map[string]interface{}{},
	}

	if r.Method == http.MethodPost {
		if !validateCSRF(r) {
			pd.Error = "Invalid request. Please try again."
		} else {
			action := r.FormValue("action")
			holdID, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
			if err != nil {
				pd.Error = "Invalid hold ID."
			} else {
				op := s.currentOperator(r)
				var opID int64
				if op != nil {
					opID = op.ID
				}
				switch action {
				case "approve":
					if err := s.db.UpdateHold(holdID, "approved", opID); err != nil {
						pd.Error = "Could not approve hold: " + err.Error()
					} else {
						queueID, err := s.db.GetQueueIDFromHold(holdID)
						if err == nil {
							_ = s.db.UpdateQueueStatus(queueID, "queued")
						}
						_ = s.audit.LogHoldApproved(r.Context(), fmt.Sprintf("%d", opID), fmt.Sprintf("%d", holdID))
						pd.Success = "Message released and re-queued for sending."
					}
				case "reject":
					if err := s.db.UpdateHold(holdID, "rejected", opID); err != nil {
						pd.Error = "Could not reject hold: " + err.Error()
					} else {
						queueID, err := s.db.GetQueueIDFromHold(holdID)
						if err == nil {
							_ = s.db.UpdateQueueStatus(queueID, "rejected")
						}
						_ = s.audit.LogHoldRejected(r.Context(), fmt.Sprintf("%d", opID), fmt.Sprintf("%d", holdID))
						pd.Success = "Message denied. It will not be sent."
					}
				default:
					pd.Error = "Unknown action."
				}
			}
		}
	}

	statusFilter := r.URL.Query().Get("status")
	pd.Data["StatusFilter"] = statusFilter

	holds, err := s.db.ListAllHolds(statusFilter)
	if err != nil {
		slog.Error("list holds", "error", err)
	}
	pd.Data["Holds"] = holds

	s.render(w, r, "holds.html", pd)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Audit Trail",
		CurrentPage: "audit",
		Data:        map[string]interface{}{},
	}

	actorType := r.URL.Query().Get("actor_type")
	actionFilter := r.URL.Query().Get("action")
	fromDate := r.URL.Query().Get("from")
	toDate := r.URL.Query().Get("to")
	pageStr := r.URL.Query().Get("page")

	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	const perPage = 50
	offset := (page - 1) * perPage

	events, total, err := s.db.ListFilteredAuditEvents(actorType, actionFilter, fromDate, toDate, perPage, offset)
	if err != nil {
		slog.Error("list audit events", "error", err)
	}

	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}

	pd.Data["Events"] = events
	pd.Data["ActorTypeFilter"] = actorType
	pd.Data["ActionFilter"] = actionFilter
	pd.Data["FromDate"] = fromDate
	pd.Data["ToDate"] = toDate
	pd.Data["Page"] = page
	pd.Data["TotalPages"] = totalPages
	pd.Data["PrevPage"] = page - 1
	pd.Data["NextPage"] = page + 1

	s.render(w, r, "audit.html", pd)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	pd := &PageData{
		Title:       "Settings",
		CurrentPage: "settings",
		Data:        map[string]interface{}{},
	}

	settingKeys := []struct {
		key      string
		dataKey  string
		fallback string
	}{
		{"retention_metadata_days", "RetentionMetadataDays", "90"},
		{"retention_body_days", "RetentionBodyDays", "30"},
		{"retention_attachment_days", "RetentionAttachmentDays", "14"},
		{"retention_audit_days", "RetentionAuditDays", "365"},
		{"retention_queue_days", "RetentionQueueDays", "30"},
		{"mcp_session_timeout_minutes", "MCPSessionTimeoutMinutes", "60"},
	}

	if r.Method == http.MethodPost {
		if !validateCSRF(r) {
			pd.Error = "Invalid request. Please try again."
		} else {
			for _, sk := range settingKeys {
				val := strings.TrimSpace(r.FormValue(sk.key))
				if val != "" {
					if err := s.db.SetSystemSetting(sk.key, val); err != nil {
						pd.Error = "Could not save settings: " + err.Error()
						break
					}
				}
			}
			if pd.Error == "" {
				pd.Success = "Settings saved."
			}
		}
	}

	for _, sk := range settingKeys {
		val, err := s.db.GetSystemSetting(sk.key)
		if err != nil || val == "" {
			val = sk.fallback
		}
		pd.Data[sk.dataKey] = val
	}

	stats, err := s.db.GetStorageStats()
	if err != nil {
		slog.Error("storage stats", "error", err)
		stats = &db.StorageStats{}
	}
	if s.store != nil {
		diskBytes, err := s.store.DiskUsage()
		if err != nil {
			slog.Error("disk usage", "error", err)
		} else {
			stats.StorageDiskBytes = diskBytes
		}
	}
	pd.Data["Storage"] = stats

	s.render(w, r, "settings.html", pd)
}
