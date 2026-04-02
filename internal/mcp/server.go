// Package mcp provides the MCP tool-dispatch server that exposes mail gateway
// operations to authenticated agents over the JSON-RPC 2.0 Streamable HTTP transport.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luxemque/msngr/internal/audit"
	"github.com/luxemque/msngr/internal/db"
	"github.com/luxemque/msngr/internal/model"
	"github.com/luxemque/msngr/internal/policy"
	"github.com/luxemque/msngr/internal/storage"
)

// Server is the MCP tool-dispatch server.
type Server struct {
	db        *db.DB
	policy    *policy.Engine
	store     *storage.Store
	audit     *audit.Logger
	mcpServer *sdkmcp.Server

	// sessions maps MCP session IDs to authenticated MCPSessions.
	// The MCP SDK's Streamable HTTP transport does not propagate per-request
	// HTTP context to tool handlers. The authMiddleware stores the session here
	// keyed by session ID, and withAuth injects it before tool handlers run.
	sessions   map[string]*model.MCPSession
	sessionsMu sync.RWMutex

	sessionTimeout time.Duration // fallback if DB has no setting
}

// getSessionTimeout returns the current session timeout, reading from DB if available.
func (s *Server) getSessionTimeout() time.Duration {
	val, err := s.db.GetSystemSetting("mcp_session_timeout_minutes")
	if err == nil && val != "" {
		var minutes int
		if _, err := fmt.Sscanf(val, "%d", &minutes); err == nil && minutes > 0 {
			return time.Duration(minutes) * time.Minute
		}
	}
	return s.sessionTimeout
}

// toolFunc is the signature for individual tool handlers.
// The context carries the authenticated MCPSession.
type toolFunc func(ctx context.Context, params map[string]interface{}) *ToolResponse

// ToolResponse is the standard response envelope for every MCP tool.
type ToolResponse struct {
	OK            bool        `json:"ok"`
	ErrorCode     string      `json:"error_code,omitempty"`
	Message       string      `json:"message,omitempty"`
	Data          interface{} `json:"data,omitempty"`
	Details       interface{} `json:"details,omitempty"`
	Retryable     bool        `json:"retryable,omitempty"`
	MatchedRule   string      `json:"matched_rule,omitempty"`
	Suggestion    string      `json:"suggestion,omitempty"`
	CorrelationID string      `json:"correlation_id,omitempty"`
}

// NewServer creates a new MCP server wired to the given database, policy engine, and storage.
// The store parameter may be nil if filesystem storage is not configured.
func NewServer(database *db.DB, policyEngine *policy.Engine, store *storage.Store, version string, sessionTimeoutMinutes int) *Server {
	timeout := time.Duration(sessionTimeoutMinutes) * time.Minute
	if timeout <= 0 {
		timeout = 60 * time.Minute
	}
	s := &Server{
		db:             database,
		policy:         policyEngine,
		store:          store,
		audit:          audit.NewLogger(database),
		sessions:       make(map[string]*model.MCPSession),
		sessionTimeout: timeout,
	}

	if version == "" {
		version = "0.0.0-dev"
	}
	impl := &sdkmcp.Implementation{
		Name:    "msngr",
		Title:   "MSNGR — Mail Secure Network Gateway Relay",
		Version: version,
	}
	mcpServer := sdkmcp.NewServer(impl, nil)
	s.mcpServer = mcpServer
	s.registerTools(mcpServer)
	return s
}

// Handler returns an http.Handler that serves the MCP JSON-RPC 2.0 protocol
// via the Streamable HTTP transport, with Bearer token authentication.
func (s *Server) Handler() http.Handler {
	streamableHandler := sdkmcp.NewStreamableHTTPHandler(
		func(r *http.Request) *sdkmcp.Server { return s.mcpServer },
		&sdkmcp.StreamableHTTPOptions{},
	)
	return s.authMiddleware(streamableHandler)
}

// --- Authentication ---

// authMiddleware extracts the Bearer token from the Authorization header,
// validates it, and stores the session in the session map for tool handlers.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			plainToken := strings.TrimPrefix(authHeader, "Bearer ")

			// Check if we already have a session for this token (avoid repeated DB lookups).
			sessionID := r.Header.Get("Mcp-Session")
			s.sessionsMu.RLock()
			existing := s.sessions[sessionID]
			if existing == nil {
				existing = s.sessions["token:"+plainToken]
			}
			s.sessionsMu.RUnlock()

			if existing != nil {
				// Check expiry.
				if time.Since(existing.AuthenticatedAt) > s.getSessionTimeout() {
					slog.Warn("MCP session expired", "agent", existing.Agent.DisplayName)
					s.sessionsMu.Lock()
					delete(s.sessions, sessionID)
					delete(s.sessions, "token:"+plainToken)
					s.sessionsMu.Unlock()
				} else {
					r = r.WithContext(withSession(r.Context(), existing))
					next.ServeHTTP(w, r)
					return
				}
			}

			token, err := s.db.LookupAgentToken(plainToken)
			if err != nil {
				slog.Error("token lookup failed", "error", err)
			}
			if token != nil {
				// Build full Agent struct for the session.
				agent, err := s.db.GetAgentByID(token.AgentID)
				if err != nil || agent == nil {
					slog.Error("agent lookup failed", "agent_id", token.AgentID, "error", err)
					next.ServeHTTP(w, r)
					return
				}

				session := &model.MCPSession{
					Agent:           agent,
					Token:           token,
					AuthenticatedAt: time.Now(),
				}

				// Update last-used timestamp (fire-and-forget).
				go func() {
					if err := s.db.UpdateTokenLastUsed(token.ID); err != nil {
						slog.Error("update token last used", "error", err)
					}
				}()

				// Store session keyed by session ID and by token fallback.
				s.sessionsMu.Lock()
				if sessionID != "" {
					s.sessions[sessionID] = session
				}
				s.sessions["token:"+plainToken] = session
				s.sessionsMu.Unlock()

				r = r.WithContext(withSession(r.Context(), session))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// withAuth wraps a tool handler to inject the authenticated MCPSession from the session map.
func (s *Server) withAuth(handler toolFunc) func(context.Context, *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		// Try to get session from context first (set by authMiddleware).
		session := getSession(ctx)

		// Fall back to session map lookup.
		if session == nil && req.Session != nil {
			sessionID := req.Session.ID()
			s.sessionsMu.RLock()
			session = s.sessions[sessionID]
			s.sessionsMu.RUnlock()
		}

		if session == nil {
			return mcpToolError("AUTHENTICATION_REQUIRED", "Invalid or missing API token."), nil
		}

		// Check expiry.
		if time.Since(session.AuthenticatedAt) > s.getSessionTimeout() {
			return mcpToolError("SESSION_EXPIRED", "MCP session has expired. Please reconnect."), nil
		}

		ctx = withSession(ctx, session)
		slog.Info("MCP tool invoked", "tool", req.Params.Name, "agent", session.Agent.DisplayName, "account_id", session.SelectedAccountID)

		// Parse arguments and call the original handler.
		params := parseArgs(req)
		resp := handler(ctx, params)
		return convertResponse(resp), nil
	}
}

// --- Session context helpers ---

type sessionContextKey struct{}

func withSession(ctx context.Context, s *model.MCPSession) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, s)
}

func getSession(ctx context.Context) *model.MCPSession {
	s, _ := ctx.Value(sessionContextKey{}).(*model.MCPSession)
	return s
}

// requireAccountSelected returns an error response if no account is selected in the session.
func requireAccountSelected(session *model.MCPSession) *ToolResponse {
	if session.SelectedAccountID == 0 {
		return &ToolResponse{
			OK:        false,
			ErrorCode: "NO_ACCOUNT_SELECTED",
			Message:   "No account selected. Call msngr_select_account first.",
		}
	}
	return nil
}

// --- Tool registration ---

func (s *Server) registerTools(mcpServer *sdkmcp.Server) {
	// Session — unauthenticated (this is the login entry point)
	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_login",
			Description: "Authenticate with the MSNGR gateway using agent email and API token. Must be called before any other tool.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"login_email": map[string]interface{}{
						"type":        "string",
						"description": "Agent email address (e.g. claude@sys.lu)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "API token for the agent",
					},
				},
				"required": []string{"login_email", "token"},
			},
		},
		s.toolLogin, // No withAuth — this IS the authentication tool
	)

	// Inbound
	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_list_messages",
			Description: "List messages in a mail folder for the authenticated agent's account",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"folder": map[string]interface{}{
						"type":        "string",
						"description": "Mail folder name (default: INBOX)",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of messages to return (default: 50)",
					},
				},
			},
		},
		s.withAuth(s.toolListMessages),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_read_message",
			Description: "Read a single message including its body text and HTML",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"message_id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the message to read",
					},
				},
				"required": []string{"message_id"},
			},
		},
		s.withAuth(s.toolReadMessage),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_search_messages",
			Description: "Search messages by subject, sender, or recipient",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query string",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of results (default: 50)",
					},
				},
				"required": []string{"query"},
			},
		},
		s.withAuth(s.toolSearchMessages),
	)

	// Outbound
	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_request_send",
			Description: "Request to send an email — evaluates policy, then queues or holds the message",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"to": map[string]interface{}{
						"type":        "string",
						"description": "Comma-separated recipient email addresses",
					},
					"subject": map[string]interface{}{
						"type":        "string",
						"description": "Email subject line",
					},
					"body_text": map[string]interface{}{
						"type":        "string",
						"description": "Plain text email body",
					},
					"body_html": map[string]interface{}{
						"type":        "string",
						"description": "Optional HTML email body",
					},
					"cc": map[string]interface{}{
						"type":        "string",
						"description": "Comma-separated CC addresses",
					},
					"attachments": map[string]interface{}{
						"type":        "array",
						"description": "File attachments (base64-encoded)",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"filename": map[string]interface{}{
									"type":        "string",
									"description": "Filename including extension (e.g. report.pdf)",
								},
								"mime_type": map[string]interface{}{
									"type":        "string",
									"description": "MIME type (e.g. application/pdf). Defaults to application/octet-stream",
								},
								"content_base64": map[string]interface{}{
									"type":        "string",
									"description": "File content encoded as base64",
								},
							},
							"required": []string{"filename", "content_base64"},
						},
					},
				},
				"required": []string{"to", "subject", "body_text"},
			},
		},
		s.withAuth(s.toolRequestSend),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_validate_send",
			Description: "Dry-run policy evaluation for a send request without actually queuing the message",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"to": map[string]interface{}{
						"type":        "string",
						"description": "Comma-separated recipient email addresses",
					},
					"subject": map[string]interface{}{
						"type":        "string",
						"description": "Email subject line",
					},
					"body_text": map[string]interface{}{
						"type":        "string",
						"description": "Plain text email body",
					},
					"cc": map[string]interface{}{
						"type":        "string",
						"description": "Comma-separated CC addresses",
					},
				},
				"required": []string{"to", "subject", "body_text"},
			},
		},
		s.withAuth(s.toolValidateSend),
	)

	// Actions
	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_mark_message",
			Description: "Mark a message with a flag (read, unread, or flagged)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"message_id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the message to mark",
					},
					"flag": map[string]interface{}{
						"type":        "string",
						"description": "Flag to apply: read, unread, or flagged",
						"enum":        []string{"read", "unread", "flagged"},
					},
				},
				"required": []string{"message_id", "flag"},
			},
		},
		s.withAuth(s.toolMarkMessage),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_delete_message",
			Description: "Delete a message (subject to policy evaluation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"message_id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the message to delete",
					},
				},
				"required": []string{"message_id"},
			},
		},
		s.withAuth(s.toolDeleteMessage),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_download_attachment",
			Description: "Download an attachment from a message (requires download_attachment capability)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"message_id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the message containing the attachment",
					},
					"filename": map[string]interface{}{
						"type":        "string",
						"description": "Name of the attachment file to download",
					},
				},
				"required": []string{"message_id", "filename"},
			},
		},
		s.withAuth(s.toolDownloadAttachment),
	)

	// Admin
	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_list_holds",
			Description: "List held messages awaiting operator review",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"status": map[string]interface{}{
						"type":        "string",
						"description": "Filter by hold status (default: pending)",
					},
				},
			},
		},
		s.withAuth(s.toolListHolds),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_review_hold",
			Description: "Approve or reject a held message",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"hold_id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the hold to review",
					},
					"action": map[string]interface{}{
						"type":        "string",
						"description": "Review action: approve or reject",
						"enum":        []string{"approve", "reject"},
					},
				},
				"required": []string{"hold_id", "action"},
			},
		},
		s.withAuth(s.toolReviewHold),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_explain_decision",
			Description: "Retrieve audit events and rule matches for a correlation ID",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"correlation_id": map[string]interface{}{
						"type":        "string",
						"description": "Correlation ID from a previous send request",
					},
				},
				"required": []string{"correlation_id"},
			},
		},
		s.withAuth(s.toolExplainDecision),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_list_accounts",
			Description: "List mail accounts the agent has permission to access",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		s.withAuth(s.toolListAccounts),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_select_account",
			Description: "Select a mail account for the current session. Must be called before using account-scoped tools.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"account_id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the account to select (from msngr_list_accounts)",
					},
				},
				"required": []string{"account_id"},
			},
		},
		s.withAuth(s.toolSelectAccount),
	)

	mcpServer.AddTool(
		&sdkmcp.Tool{
			Name:        "msngr_test_account_connectivity",
			Description: "Test IMAP and SMTP connectivity for a mail account",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"account_id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the account to test",
					},
				},
				"required": []string{"account_id"},
			},
		},
		s.withAuth(s.toolTestAccountConnectivity),
	)
}

// --- Response conversion ---

// convertResponse converts an internal ToolResponse to an MCP SDK CallToolResult.
func convertResponse(resp *ToolResponse) *sdkmcp.CallToolResult {
	data, err := json.Marshal(resp)
	if err != nil {
		return mcpToolError("INTERNAL_ERROR", "failed to encode response")
	}
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{
			&sdkmcp.TextContent{Text: string(data)},
		},
		IsError: !resp.OK,
	}
}

// mcpToolError creates an MCP error result.
func mcpToolError(code, message string) *sdkmcp.CallToolResult {
	resp := &ToolResponse{
		OK:        false,
		ErrorCode: code,
		Message:   message,
	}
	data, _ := json.Marshal(resp)
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{
			&sdkmcp.TextContent{Text: string(data)},
		},
		IsError: true,
	}
}

// --- Argument parsing ---

// parseArgs extracts tool arguments from an MCP SDK CallToolRequest.
func parseArgs(req *sdkmcp.CallToolRequest) map[string]interface{} {
	if req.Params == nil || req.Params.Arguments == nil {
		return make(map[string]interface{})
	}
	var args map[string]interface{}
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		return make(map[string]interface{})
	}
	return args
}

// --- Parameter extraction helpers (used by tool handlers) ---

func paramString(params map[string]interface{}, key string) string {
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func paramInt64(params map[string]interface{}, key string) (int64, bool) {
	v, ok := params[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func paramIntDefault(params map[string]interface{}, key string, def int) int {
	v, ok := paramInt64(params, key)
	if !ok {
		return def
	}
	return int(v)
}

func paramStringDefault(params map[string]interface{}, key, def string) string {
	s := paramString(params, key)
	if s == "" {
		return def
	}
	return s
}

func errorResponse(code, message string) *ToolResponse {
	return &ToolResponse{
		OK:        false,
		ErrorCode: code,
		Message:   message,
	}
}
