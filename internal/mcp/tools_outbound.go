package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/luxemque/msngr/internal/audit"
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

	if errResp := s.requireCapability(ctx, capabilitySend); errResp != nil {
		return nil, errResp
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

	session := getSession(ctx)
	agentID := session.Agent.ID

	// The correlation ID is minted before the decision, not by the queue insert.
	// A denied send never reaches the queue, and a denial with no correlation ID is
	// invisible to msngr_explain_decision — exactly the case someone will ask about.
	correlationID := queue.NewCorrelationID()

	item := &model.OutboundItem{
		AccountID:       action.AccountID,
		AgentID:         &agentID,
		CorrelationID:   correlationID,
		FromAddr:        action.FromAddr,
		ToAddrs:         toJSON,
		CcAddrs:         ccJSON,
		Subject:         action.Subject,
		BodyText:        action.BodyText,
		BodyHTML:        bodyHTML,
		AttachmentsJSON: attachmentsJSON,
	}

	// Every outcome records who the message was addressed to. A held, rejected or
	// denied message is precisely when that question gets asked.
	requestDetails := map[string]any{
		"account_id":         fmt.Sprintf("%d", action.AccountID),
		"agent_display_name": session.Agent.DisplayName,
		"from":               action.FromAddr,
		"to":                 action.ToAddrs,
		"cc":                 orEmptyAddrs(action.CcAddrs),
		"subject":            action.Subject,
		"attachment_count":   len(action.Attachments),
	}

	switch decision.Outcome {
	case "deny":
		matchedRule := decision.FinalRuleName()
		requestDetails["reason"] = decision.Explanation
		requestDetails["matched_rule"] = matchedRule
		_ = s.audit.LogStructured(ctx, audit.Event{
			ActorType:     "agent",
			ActorID:       fmt.Sprintf("%d", agentID),
			Action:        "send_denied",
			TargetType:    "account",
			TargetID:      fmt.Sprintf("%d", action.AccountID),
			Outcome:       "denied",
			CorrelationID: correlationID,
		}, requestDetails)
		return &ToolResponse{
			OK:            false,
			ErrorCode:     "POLICY_DENIED",
			Message:       decision.Explanation,
			MatchedRule:   matchedRule,
			Suggestion:    "review the policy rules or modify the message",
			CorrelationID: correlationID,
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
		requestDetails["queue_id"] = queueID
		requestDetails["rule_id"] = fmt.Sprintf("%d", ruleID)
		requestDetails["matched_rule"] = matchedRule
		requestDetails["reason"] = decision.Explanation
		_ = s.audit.LogStructured(ctx, audit.Event{
			ActorType:     "agent",
			ActorID:       fmt.Sprintf("%d", agentID),
			Action:        "message_held",
			TargetType:    "outbound_queue",
			TargetID:      fmt.Sprintf("%d", queueID),
			Outcome:       "held",
			CorrelationID: correlationID,
		}, requestDetails)
		return &ToolResponse{
			OK:            true,
			Message:       "message held for review",
			Data:          map[string]interface{}{"queue_id": queueID, "status": "held"},
			MatchedRule:   matchedRule,
			CorrelationID: correlationID,
		}

	default: // allow
		queueID, err := queue.QueueMessage(s.db, item)
		if err != nil {
			slog.Error("queue message", "error", err)
			return errorResponse("INTERNAL_ERROR", "failed to queue message")
		}

		requestDetails["queue_id"] = queueID
		// Outcome is "accepted", not "success": at this point the gateway has agreed to
		// try, nothing has been transmitted. The send_completed/send_failed event that
		// the queue processor writes under this same correlation ID is the one that
		// reports transmission.
		_ = s.audit.LogStructured(ctx, audit.Event{
			ActorType:     "agent",
			ActorID:       fmt.Sprintf("%d", agentID),
			Action:        "send_requested",
			TargetType:    "outbound_queue",
			TargetID:      fmt.Sprintf("%d", queueID),
			Outcome:       "accepted",
			CorrelationID: correlationID,
		}, requestDetails)
		return &ToolResponse{
			OK:      true,
			Message: "message queued for sending",
			Data: map[string]interface{}{
				"queue_id": queueID,
				"status":   "queued",
				"note":     "queued means policy passed and the gateway will attempt delivery; call msngr_queue_status to confirm transmission",
			},
			CorrelationID: correlationID,
		}
	}
}

// orEmptyAddrs renders a nil address slice as an empty JSON array rather than null.
func orEmptyAddrs(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
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

// queueStatusMeaning explains a queue state in the terms an agent needs: has the
// message been transmitted, is it waiting, or is it never going to be sent.
var queueStatusMeaning = map[string]string{
	queue.StatusDraftRequested:   "accepted but not yet queued",
	queue.StatusValidationFailed: "rejected before queueing; it will not be sent",
	queue.StatusQueued:           "policy passed and the gateway will attempt delivery; not yet transmitted",
	queue.StatusHeld:             "awaiting operator review; it will not be sent until approved",
	queue.StatusRejected:         "an operator rejected it; it will not be sent",
	queue.StatusSending:          "a delivery attempt is in flight",
	queue.StatusSent:             "accepted by the SMTP server; see last_smtp_response for the server's reply",
	queue.StatusFailed:           "the delivery attempt failed; see error_message",
	queue.StatusCancelled:        "cancelled by an operator; it will not be sent",
}

// toolQueueStatus reports the delivery state of a previously requested send.
//
// Without it "queued" is terminal from the agent's side: there is no transition to
// observe, so a message that was delivered and one that failed look the same.
func (s *Server) toolQueueStatus(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)

	queueID, ok := paramInt64(params, "queue_id")
	if !ok {
		return errorResponse("INVALID_PARAMS", "queue_id is required and must be a number")
	}

	item, err := s.db.GetQueueItemForAgent(ctx, queueID, session.Agent.ID)
	if err != nil {
		slog.Error("get queue item", "error", err, "queue_id", queueID)
		return errorResponse("INTERNAL_ERROR", "failed to look up queue item")
	}
	if item == nil {
		// Not found and not permitted are deliberately the same answer: distinguishing
		// them would let an agent probe for queue items on accounts it cannot access.
		return errorResponse("NOT_FOUND", "no queue item with that ID is visible to this agent")
	}

	var toAddrs, ccAddrs []string
	_ = json.Unmarshal([]byte(item.ToAddrs), &toAddrs)
	if item.CcAddrs != "" {
		_ = json.Unmarshal([]byte(item.CcAddrs), &ccAddrs)
	}

	data := map[string]interface{}{
		"queue_id":       item.ID,
		"status":         item.Status,
		"means":          queueStatusMeaning[item.Status],
		"account_id":     item.AccountID,
		"correlation_id": item.CorrelationID,
		"from":           item.FromAddr,
		"to":             orEmptyAddrs(toAddrs),
		"cc":             orEmptyAddrs(ccAddrs),
		"subject":        item.Subject,
		"attempts":       item.Attempts,
		"created_at":     item.CreatedAt,
		"updated_at":     item.UpdatedAt,
	}
	if item.SentAt != nil {
		data["sent_at"] = *item.SentAt
	}
	if item.ErrorMessage != "" {
		data["last_error"] = item.ErrorMessage
	}
	if item.LastAttemptAt != "" {
		data["last_attempt_at"] = item.LastAttemptAt
	}
	if item.LastSMTPResponse != "" {
		data["last_smtp_response"] = item.LastSMTPResponse
	}
	if item.HoldStatus != "" {
		data["hold_status"] = item.HoldStatus
		data["hold_reason"] = item.HoldReason
	}

	return &ToolResponse{
		OK:            true,
		Message:       fmt.Sprintf("queue item %d is %s", item.ID, item.Status),
		Data:          data,
		CorrelationID: item.CorrelationID,
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
