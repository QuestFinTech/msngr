package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/luxemque/msngr/internal/model"
	"github.com/luxemque/msngr/internal/policy"
	"github.com/luxemque/msngr/internal/queue"
)

// buildSendAction constructs a policy.Action from the common send parameters.
func (s *Server) buildSendAction(ctx context.Context, params map[string]interface{}) (*policy.Action, *ToolResponse) {
	session := getSession(ctx)
	if errResp := requireAccountSelected(session); errResp != nil {
		return nil, errResp
	}
	accountID := session.SelectedAccountID

	to := paramString(params, "to")
	if to == "" {
		return nil, errorResponse("INVALID_PARAMS", "to is required")
	}
	subject := paramString(params, "subject")
	if subject == "" {
		return nil, errorResponse("INVALID_PARAMS", "subject is required")
	}
	bodyText := paramString(params, "body_text")
	if bodyText == "" {
		return nil, errorResponse("INVALID_PARAMS", "body_text is required")
	}

	cc := paramString(params, "cc")

	// Look up the account to get from address.
	acct, err := s.db.GetAccountByID(accountID)
	if err != nil {
		slog.Error("get account", "error", err)
		return nil, errorResponse("INTERNAL_ERROR", "failed to look up account")
	}
	if acct == nil {
		return nil, errorResponse("NOT_FOUND", "account not found")
	}
	if !acct.SendingEnabled {
		return nil, errorResponse("ACCESS_DENIED", "sending is disabled for this account")
	}

	// Verify agent has the "send" capability on this account.
	hasSend, err := s.db.CheckAgentCapability(ctx, session.Agent.ID, accountID, "send")
	if err != nil {
		slog.Error("check send capability", "error", err)
		return nil, errorResponse("INTERNAL_ERROR", "failed to verify send capability")
	}
	if !hasSend {
		return nil, errorResponse("ACCESS_DENIED", "agent does not have send permission on this account")
	}

	toAddrs := splitAddrs(to)
	ccAddrs := splitAddrs(cc)

	// Parse attachments if provided.
	var policyAttachments []policy.AttachmentInfo
	if raw, ok := params["attachments"]; ok && raw != nil {
		attJSON, err := json.Marshal(raw)
		if err != nil {
			return nil, errorResponse("INVALID_PARAMS", "invalid attachments format")
		}
		var atts []model.Attachment
		if err := json.Unmarshal(attJSON, &atts); err != nil {
			return nil, errorResponse("INVALID_PARAMS", "invalid attachments: "+err.Error())
		}
		for _, a := range atts {
			if a.Filename == "" || a.ContentBase64 == "" {
				return nil, errorResponse("INVALID_PARAMS", "each attachment requires filename and content_base64")
			}
			decoded, err := base64.StdEncoding.DecodeString(a.ContentBase64)
			if err != nil {
				return nil, errorResponse("INVALID_PARAMS", "invalid base64 in attachment "+a.Filename)
			}
			mimeType := a.MimeType
			if mimeType == "" {
				mimeType = "application/octet-stream"
			}
			policyAttachments = append(policyAttachments, policy.AttachmentInfo{
				Filename: a.Filename,
				MimeType: mimeType,
				Size:     int64(len(decoded)),
			})
		}
	}

	action := &policy.Action{
		Type:           "send",
		AgentName:      session.Agent.DisplayName,
		AgentNumericID: session.Agent.ID,
		AccountID:      accountID,
		FromAddr:       acct.EmailAddress,
		ToAddrs:        toAddrs,
		CcAddrs:        ccAddrs,
		Subject:        subject,
		BodyText:       bodyText,
		Attachments:    policyAttachments,
	}
	return action, nil
}

// toolRequestSend evaluates policy and queues or holds the message.
func (s *Server) toolRequestSend(ctx context.Context, params map[string]interface{}) *ToolResponse {
	action, errResp := s.buildSendAction(ctx, params)
	if errResp != nil {
		return errResp
	}

	decision, err := s.policy.Evaluate(ctx, *action)
	if err != nil {
		slog.Error("policy evaluation", "error", err)
		return errorResponse("INTERNAL_ERROR", "policy evaluation failed")
	}

	toJSON := marshalAddrs(action.ToAddrs)
	ccJSON := marshalAddrs(action.CcAddrs)
	bodyHTML := paramString(params, "body_html")

	// Marshal attachments JSON for storage.
	var attachmentsJSON string
	if raw, ok := params["attachments"]; ok && raw != nil {
		attJSON, _ := json.Marshal(raw)
		attachmentsJSON = string(attJSON)
	}

	item := &model.OutboundItem{
		AccountID:       action.AccountID,
		FromAddr:        action.FromAddr,
		ToAddrs:         toJSON,
		CcAddrs:         ccJSON,
		Subject:         action.Subject,
		BodyText:        action.BodyText,
		BodyHTML:        bodyHTML,
		AttachmentsJSON: attachmentsJSON,
	}

	session := getSession(ctx)
	agentName := session.Agent.DisplayName
	accountIDStr := fmt.Sprintf("%d", action.AccountID)

	switch decision.Outcome {
	case "deny":
		matchedRule := decision.FinalRuleName()
		_ = s.audit.LogSendDenied(ctx, agentName, decision.Explanation, item.CorrelationID)
		return &ToolResponse{
			OK:          false,
			ErrorCode:   "POLICY_DENIED",
			Message:     decision.Explanation,
			MatchedRule: matchedRule,
			Suggestion:  "review the policy rules or modify the message",
		}

	case "hold":
		// Queue, then hold.
		queueID, err := queue.QueueMessage(s.db, item)
		if err != nil {
			slog.Error("queue message", "error", err)
			return errorResponse("INTERNAL_ERROR", "failed to queue message")
		}

		ruleID := int64(0)
		if decision.FinalRule != nil {
			ruleID = decision.FinalRule.RuleID
		}
		if err := queue.HoldMessage(s.db, queueID, ruleID, decision.Explanation); err != nil {
			slog.Error("hold message", "error", err)
			return errorResponse("INTERNAL_ERROR", "failed to hold message")
		}

		matchedRule := decision.FinalRuleName()
		_ = s.audit.LogMessageHeld(ctx, agentName, fmt.Sprintf("%d", ruleID), item.CorrelationID)
		return &ToolResponse{
			OK:            true,
			Message:       "message held for review",
			Data:          map[string]interface{}{"queue_id": queueID, "status": "held"},
			MatchedRule:   matchedRule,
			CorrelationID: item.CorrelationID,
		}

	default: // allow
		queueID, err := queue.QueueMessage(s.db, item)
		if err != nil {
			slog.Error("queue message", "error", err)
			return errorResponse("INTERNAL_ERROR", "failed to queue message")
		}

		_ = s.audit.LogSendRequested(ctx, agentName, accountIDStr, item.CorrelationID)
		return &ToolResponse{
			OK:            true,
			Message:       "message queued for sending",
			Data:          map[string]interface{}{"queue_id": queueID, "status": "queued"},
			CorrelationID: item.CorrelationID,
		}
	}
}

// toolValidateSend is a dry-run that evaluates policy without queuing.
func (s *Server) toolValidateSend(ctx context.Context, params map[string]interface{}) *ToolResponse {
	action, errResp := s.buildSendAction(ctx, params)
	if errResp != nil {
		return errResp
	}

	decision, err := s.policy.Evaluate(ctx, *action)
	if err != nil {
		slog.Error("policy evaluation", "error", err)
		return errorResponse("INTERNAL_ERROR", "policy evaluation failed")
	}

	matchedRule := decision.FinalRuleName()

	return &ToolResponse{
		OK:      true,
		Message: "dry-run policy evaluation complete",
		Data: map[string]interface{}{
			"outcome":       decision.Outcome,
			"explanation":   decision.Explanation,
			"matched_rules": decision.MatchedRules,
		},
		MatchedRule: matchedRule,
	}
}

// splitAddrs splits a comma-separated address list.
func splitAddrs(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// marshalAddrs converts a string slice to a JSON array string.
func marshalAddrs(addrs []string) string {
	if len(addrs) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(addrs)
	return string(b)
}
