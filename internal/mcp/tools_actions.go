package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/luxemque/msngr/internal/policy"
)

// toolMarkMessage marks a message with a flag (read, unread, flagged).
func (s *Server) toolMarkMessage(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	if errResp := requireAccountSelected(session); errResp != nil {
		return errResp
	}
	accountID := session.SelectedAccountID

	messageID, ok := paramInt64(params, "message_id")
	if !ok {
		return errorResponse("INVALID_PARAMS", "message_id is required and must be a number")
	}
	flag := paramString(params, "flag")
	if flag == "" {
		return errorResponse("INVALID_PARAMS", "flag is required (read, unread, flagged)")
	}
	if flag != "read" && flag != "unread" && flag != "flagged" {
		return errorResponse("INVALID_PARAMS", "flag must be one of: read, unread, flagged")
	}

	// Verify message exists.
	msg, err := s.db.GetMessage(accountID, messageID)
	if err != nil {
		slog.Error("get message", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to get message")
	}
	if msg == nil {
		return errorResponse("NOT_FOUND", "message not found")
	}

	if err := s.db.UpdateMessageFlag(messageID, flag); err != nil {
		slog.Error("update message flag", "error", err, "message_id", messageID, "flag", flag)
		return errorResponse("INTERNAL_ERROR", "failed to update message flag")
	}

	slog.Info("mark message", "message_id", messageID, "flag", flag, "agent", session.Agent.DisplayName)

	return &ToolResponse{
		OK:      true,
		Message: "message marked as " + flag,
		Data: map[string]interface{}{
			"message_id": messageID,
			"flag":       flag,
		},
	}
}

// toolDeleteMessage deletes a message, gated by policy.
func (s *Server) toolDeleteMessage(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	if errResp := requireAccountSelected(session); errResp != nil {
		return errResp
	}
	accountID := session.SelectedAccountID

	messageID, ok := paramInt64(params, "message_id")
	if !ok {
		return errorResponse("INVALID_PARAMS", "message_id is required and must be a number")
	}

	// Verify message exists.
	msg, err := s.db.GetMessage(accountID, messageID)
	if err != nil {
		slog.Error("get message", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to get message")
	}
	if msg == nil {
		return errorResponse("NOT_FOUND", "message not found")
	}

	// Evaluate policy for delete action.
	action := policy.Action{
		Type:           "delete",
		AgentName:      session.Agent.DisplayName,
		AgentNumericID: session.Agent.ID,
		AccountID:      accountID,
	}
	decision, err := s.policy.Evaluate(ctx, action)
	if err != nil {
		slog.Error("policy evaluation for delete", "error", err)
		return errorResponse("INTERNAL_ERROR", "policy evaluation failed")
	}
	if decision.Outcome == "deny" {
		matchedRule := decision.FinalRuleName()
		return &ToolResponse{
			OK:          false,
			ErrorCode:   "POLICY_DENIED",
			Message:     decision.Explanation,
			MatchedRule: matchedRule,
		}
	}

	if err := s.db.DeleteMessage(messageID); err != nil {
		slog.Error("delete message", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to delete message")
	}

	_ = s.audit.LogMessageDeleted(ctx, "agent", session.Agent.DisplayName, fmt.Sprintf("%d", messageID))

	return &ToolResponse{
		OK:      true,
		Message: "message deleted",
		Data:    map[string]interface{}{"message_id": messageID},
	}
}

// toolDownloadAttachment downloads an attachment. Denied by default unless agent
// has the download_attachment capability.
func (s *Server) toolDownloadAttachment(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	if errResp := requireAccountSelected(session); errResp != nil {
		return errResp
	}
	accountID := session.SelectedAccountID

	messageID, ok := paramInt64(params, "message_id")
	if !ok {
		return errorResponse("INVALID_PARAMS", "message_id is required and must be a number")
	}
	filename := paramString(params, "filename")
	if filename == "" {
		return errorResponse("INVALID_PARAMS", "filename is required")
	}

	// Check for the specific download_attachment capability.
	hasCap, err := s.db.CheckAgentCapability(ctx, session.Agent.ID, accountID, "download_attachment")
	if err != nil {
		slog.Error("check agent capability", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to verify agent capability")
	}
	if !hasCap {
		return &ToolResponse{
			OK:         false,
			ErrorCode:  "ACCESS_DENIED",
			Message:    "agent does not have the download_attachment capability for this account",
			Suggestion: "request download_attachment permission from an administrator",
		}
	}

	// Look up the message to check if it is stored on disk.
	msg, err := s.db.GetMessage(accountID, messageID)
	if err != nil {
		slog.Error("get message for attachment", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to get message")
	}
	if msg == nil {
		return errorResponse("NOT_FOUND", "message not found")
	}

	if msg.StoredOnDisk && msg.ArchivePath != "" && s.store != nil {
		data, err := s.store.ReadAttachment(msg.ArchivePath, filename)
		if err != nil {
			slog.Error("read attachment from archive", "error", err, "archive_path", msg.ArchivePath, "filename", filename)
			return errorResponse("NOT_FOUND", "attachment not found in archive")
		}
		return &ToolResponse{
			OK:      true,
			Message: "attachment retrieved",
			Data: map[string]interface{}{
				"filename": filename,
				"data":     base64.StdEncoding.EncodeToString(data),
				"encoding": "base64",
				"size":     len(data),
			},
		}
	}

	// Message is not stored on disk; attachment cannot be retrieved.
	return errorResponse("ATTACHMENT_NOT_AVAILABLE", "attachment is not available in filesystem storage")
}
