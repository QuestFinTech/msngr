package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luxemque/msngr/internal/audit"
	"github.com/luxemque/msngr/internal/model"
	"github.com/luxemque/msngr/internal/queue"
)

// toolLogin authenticates an agent via login_email + token and creates a session.
// This is the only unauthenticated MCP tool — it is NOT wrapped with withAuth.
func (s *Server) toolLogin(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
	params := parseArgs(req)
	loginEmail := paramString(params, "login_email")
	token := paramString(params, "token")

	if loginEmail == "" || token == "" {
		return convertResponse(errorResponse("INVALID_PARAMS", "login_email and token are required")), nil
	}

	// Look up the token and verify it belongs to the claimed agent email.
	agentToken, err := s.db.LookupAgentToken(token)
	if err != nil {
		slog.Error("login token lookup failed", "error", err)
		return convertResponse(errorResponse("AUTHENTICATION_FAILED", "invalid credentials")), nil
	}
	if agentToken == nil {
		return convertResponse(errorResponse("AUTHENTICATION_FAILED", "invalid credentials")), nil
	}

	// Verify the token's agent matches the login_email.
	if agentToken.AgentEmail != loginEmail {
		slog.Warn("login email mismatch", "login_email", loginEmail, "token_agent_email", agentToken.AgentEmail)
		return convertResponse(errorResponse("AUTHENTICATION_FAILED", "invalid credentials")), nil
	}

	// Build full agent record.
	agent, err := s.db.GetAgentByID(agentToken.AgentID)
	if err != nil || agent == nil {
		slog.Error("login agent lookup failed", "agent_id", agentToken.AgentID, "error", err)
		return convertResponse(errorResponse("INTERNAL_ERROR", "failed to look up agent")), nil
	}

	session := &model.MCPSession{
		Agent:           agent,
		Token:           agentToken,
		AuthenticatedAt: time.Now(),
	}

	// Update last-used timestamp (fire-and-forget).
	go func() {
		if err := s.db.UpdateTokenLastUsed(agentToken.ID); err != nil {
			slog.Error("update token last used", "error", err)
		}
	}()

	// Store session keyed by MCP session ID.
	if req.Session != nil {
		sessionID := req.Session.ID()
		if sessionID != "" {
			s.sessionsMu.Lock()
			s.sessions[sessionID] = session
			s.sessionsMu.Unlock()
		}
	}

	slog.Info("MCP login successful", "agent", agent.DisplayName, "email", agent.AgentEmail)

	return convertResponse(&ToolResponse{
		OK:      true,
		Message: fmt.Sprintf("authenticated as %s (%s)", agent.DisplayName, agent.AgentEmail),
		Data: map[string]interface{}{
			"agent_id":     agent.ID,
			"display_name": agent.DisplayName,
			"agent_email":  agent.AgentEmail,
		},
	}), nil
}

// toolListHolds returns holds with the given status, scoped to the agent's accounts.
func (s *Server) toolListHolds(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	status := paramStringDefault(params, "status", "pending")

	holds, err := s.db.ListHoldsForAgent(ctx, session.Agent.ID, status)
	if err != nil {
		slog.Error("list holds", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to list holds")
	}

	return &ToolResponse{
		OK:      true,
		Message: fmt.Sprintf("%d hold(s) with status %q on accounts this agent can access", len(holds), status),
		Data:    holds,
		Details: map[string]interface{}{
			"status": status,
			"count":  len(holds),
			"scope":  "accounts this agent has a permission on",
		},
	}
}

// toolReviewHold approves or rejects a held message.
//
// This is a review step, so it is deliberately hard for an agent to reach. It requires
// the review_hold capability, which is not granted by default, and an agent may never
// release its own held message whatever it has been granted: a hold that the sender can
// clear is not a review, it is a delay.
func (s *Server) toolReviewHold(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)

	holdID, ok := paramInt64(params, "hold_id")
	if !ok {
		return errorResponse("INVALID_PARAMS", "hold_id is required and must be a number")
	}
	action := paramString(params, "action")
	if action != "approve" && action != "reject" {
		return errorResponse("INVALID_PARAMS", "action must be 'approve' or 'reject'")
	}

	hold, err := s.db.GetHoldContext(ctx, holdID)
	if err != nil {
		slog.Error("get hold context", "error", err, "hold_id", holdID)
		return errorResponse("INTERNAL_ERROR", "failed to look up hold")
	}
	if hold == nil {
		return errorResponse("NOT_FOUND", "no hold with that ID is visible to this agent")
	}

	hasCap, err := s.db.CheckAgentCapability(ctx, session.Agent.ID, hold.AccountID, capabilityReviewHold)
	if err != nil {
		slog.Error("check review_hold capability", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to verify agent capability")
	}
	if !hasCap {
		// Same answer whether the agent lacks the capability or cannot see the account,
		// so this cannot be used to probe for holds elsewhere.
		return &ToolResponse{
			OK:         false,
			ErrorCode:  "ACCESS_DENIED",
			Message:    "agent does not have the review_hold capability for this account",
			Suggestion: "held messages are reviewed by an operator in the MSNGR web UI",
		}
	}

	if hold.RequestedByAgentID != nil && *hold.RequestedByAgentID == session.Agent.ID {
		slog.Warn("agent attempted to review its own held message",
			"agent", session.Agent.DisplayName, "hold_id", holdID, "action", action)
		return &ToolResponse{
			OK:         false,
			ErrorCode:  "SELF_REVIEW_FORBIDDEN",
			Message:    "an agent cannot review a message it queued itself",
			Suggestion: "ask an operator to review this hold in the MSNGR web UI",
		}
	}

	if hold.Status != "pending" {
		return &ToolResponse{
			OK:        false,
			ErrorCode: "ALREADY_REVIEWED",
			Message:   fmt.Sprintf("hold %d has already been %s", holdID, hold.Status),
		}
	}

	switch action {
	case "approve":
		err = queue.ApproveHold(s.db, holdID, 0)
	case "reject":
		err = queue.RejectHold(s.db, holdID, 0)
	}
	if err != nil {
		slog.Error("review hold", "error", err, "hold_id", holdID, "action", action)
		return errorResponse("INTERNAL_ERROR", "internal error")
	}

	auditAction := "hold_approved"
	if action == "reject" {
		auditAction = "hold_rejected"
	}
	_ = s.audit.LogStructured(ctx, audit.Event{
		ActorType:  "agent",
		ActorID:    fmt.Sprintf("%d", session.Agent.ID),
		Action:     auditAction,
		TargetType: "hold",
		TargetID:   fmt.Sprintf("%d", holdID),
		Outcome:    "success",
	}, map[string]any{
		"agent_display_name": session.Agent.DisplayName,
		"queue_id":           hold.QueueID,
		"account_id":         hold.AccountID,
	})

	return &ToolResponse{
		OK:      true,
		Message: fmt.Sprintf("hold %d %sd", holdID, action),
		Data:    map[string]interface{}{"hold_id": holdID, "action": action},
	}
}

// toolExplainDecision returns audit events and rule matches for a correlation ID.
func (s *Server) toolExplainDecision(_ context.Context, params map[string]interface{}) *ToolResponse {
	correlationID := paramString(params, "correlation_id")
	if correlationID == "" {
		return errorResponse("INVALID_PARAMS", "correlation_id is required")
	}

	events, err := s.db.GetAuditByCorrelation(correlationID)
	if err != nil {
		slog.Error("get audit by correlation", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to retrieve audit events")
	}

	return &ToolResponse{
		OK:            true,
		Message:       fmt.Sprintf("found %d audit events for correlation %s", len(events), correlationID),
		Data:          events,
		CorrelationID: correlationID,
	}
}

// toolListAccounts returns accounts the agent has permission to access.
func (s *Server) toolListAccounts(ctx context.Context, _ map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	accounts, err := s.db.ListAccountsForAgent(session.Agent.ID)
	if err != nil {
		slog.Error("list accounts for agent", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to list accounts")
	}

	return &ToolResponse{
		OK:      true,
		Message: fmt.Sprintf("found %d permitted accounts", len(accounts)),
		Data:    accounts,
	}
}

// toolSelectAccount sets the active mail account for the current MCP session.
func (s *Server) toolSelectAccount(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	accountID, ok := paramInt64(params, "account_id")
	if !ok {
		return errorResponse("INVALID_PARAMS", "account_id is required and must be a number")
	}

	// Verify agent has permission for this account.
	hasAccess, err := s.db.CheckAgentAccountMapping(ctx, session.Agent.ID, accountID)
	if err != nil {
		slog.Error("check agent account mapping", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to verify account access")
	}
	if !hasAccess {
		return errorResponse("ACCESS_DENIED", "agent does not have permission for this account")
	}

	// Verify account exists and is enabled.
	acct, err := s.db.GetAccountByID(accountID)
	if err != nil {
		slog.Error("get account", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to look up account")
	}
	if acct == nil {
		return errorResponse("NOT_FOUND", "account not found")
	}
	if !acct.Enabled {
		return errorResponse("ACCOUNT_DISABLED", "account is disabled")
	}

	// Update session state (pointer — shared across all session map entries).
	session.SelectedAccountID = acct.ID
	session.SelectedAccountEmail = acct.EmailAddress

	slog.Info("MCP account selected", "agent", session.Agent.DisplayName, "account_id", acct.ID, "email", acct.EmailAddress)

	return &ToolResponse{
		OK:      true,
		Message: fmt.Sprintf("selected account %q (%s)", acct.Name, acct.EmailAddress),
		Data: map[string]interface{}{
			"account_id":    acct.ID,
			"account_name":  acct.Name,
			"email_address": acct.EmailAddress,
		},
	}
}

// toolTestAccountConnectivity tests IMAP and SMTP connectivity for an account.
func (s *Server) toolTestAccountConnectivity(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	accountID, ok := paramInt64(params, "account_id")
	if !ok {
		return errorResponse("INVALID_PARAMS", "account_id is required and must be a number")
	}

	// Verify agent has permission for this account.
	hasAccess, err := s.db.CheckAgentAccountMapping(ctx, session.Agent.ID, accountID)
	if err != nil {
		slog.Error("check agent account mapping", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to verify account access")
	}
	if !hasAccess {
		return errorResponse("ACCESS_DENIED", "agent does not have permission for this account")
	}

	acct, err := s.db.GetAccountByID(accountID)
	if err != nil {
		slog.Error("get account", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to look up account")
	}
	if acct == nil {
		return errorResponse("NOT_FOUND", "account not found")
	}

	results := map[string]interface{}{
		"account_id": accountID,
		"account":    acct.Name,
	}

	// Test IMAP connectivity.
	if acct.IMAPHost != "" {
		imapAddr := net.JoinHostPort(acct.IMAPHost, fmt.Sprintf("%d", acct.IMAPPort))
		conn, err := net.DialTimeout("tcp", imapAddr, 5*time.Second)
		if err != nil {
			slog.Error("IMAP connectivity test failed", "error", err, "address", imapAddr)
			results["imap"] = map[string]interface{}{
				"ok":    false,
				"error": "connection failed",
			}
		} else {
			conn.Close()
			results["imap"] = map[string]interface{}{
				"ok":      true,
				"address": imapAddr,
			}
		}
	} else {
		results["imap"] = map[string]interface{}{
			"ok":    false,
			"error": "IMAP host not configured",
		}
	}

	// Test SMTP connectivity.
	if acct.SMTPHost != "" {
		smtpAddr := net.JoinHostPort(acct.SMTPHost, fmt.Sprintf("%d", acct.SMTPPort))
		conn, err := net.DialTimeout("tcp", smtpAddr, 5*time.Second)
		if err != nil {
			slog.Error("SMTP connectivity test failed", "error", err, "address", smtpAddr)
			results["smtp"] = map[string]interface{}{
				"ok":    false,
				"error": "connection failed",
			}
		} else {
			conn.Close()
			results["smtp"] = map[string]interface{}{
				"ok":      true,
				"address": smtpAddr,
			}
		}
	} else {
		results["smtp"] = map[string]interface{}{
			"ok":    false,
			"error": "SMTP host not configured",
		}
	}

	return &ToolResponse{
		OK:      true,
		Message: "connectivity test complete",
		Data:    results,
	}
}
