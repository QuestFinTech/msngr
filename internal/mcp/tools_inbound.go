package mcp

import (
	"context"
	"log/slog"
)

// toolListMessages lists messages for the session's selected account in a folder.
func (s *Server) toolListMessages(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	if errResp := requireAccountSelected(session); errResp != nil {
		return errResp
	}
	accountID := session.SelectedAccountID

	folder := paramStringDefault(params, "folder", "INBOX")
	limit := paramIntDefault(params, "limit", 50)

	msgs, err := s.db.ListMessages(accountID, folder, limit)
	if err != nil {
		slog.Error("list messages", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to list messages")
	}

	return &ToolResponse{
		OK:      true,
		Message: "messages retrieved",
		Data:    msgs,
	}
}

// toolReadMessage reads a single message with its body.
func (s *Server) toolReadMessage(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	if errResp := requireAccountSelected(session); errResp != nil {
		return errResp
	}
	accountID := session.SelectedAccountID

	messageID, ok := paramInt64(params, "message_id")
	if !ok {
		return errorResponse("INVALID_PARAMS", "message_id is required and must be a number")
	}

	msg, err := s.db.GetMessage(accountID, messageID)
	if err != nil {
		slog.Error("get message", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to get message")
	}
	if msg == nil {
		return errorResponse("NOT_FOUND", "message not found")
	}

	var bodyText, bodyHTML string

	// If stored on disk, read from the archive; otherwise fall back to DB.
	if msg.StoredOnDisk && msg.ArchivePath != "" && s.store != nil {
		text, html, err := s.store.ReadBody(msg.ArchivePath)
		if err != nil {
			slog.Error("read body from archive", "error", err, "archive_path", msg.ArchivePath)
			return errorResponse("INTERNAL_ERROR", "failed to read message body from archive")
		}
		bodyText = text
		bodyHTML = html
	} else {
		text, html, err := s.db.GetMessageBody(messageID)
		if err != nil {
			slog.Error("get message body", "error", err)
			return errorResponse("INTERNAL_ERROR", "failed to get message body")
		}
		bodyText = text
		bodyHTML = html
	}

	result := map[string]interface{}{
		"message":   msg,
		"body_text": bodyText,
		"body_html": bodyHTML,
	}

	return &ToolResponse{
		OK:      true,
		Message: "message retrieved",
		Data:    result,
	}
}

// toolSearchMessages searches messages by subject/from/to.
func (s *Server) toolSearchMessages(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	if errResp := requireAccountSelected(session); errResp != nil {
		return errResp
	}
	accountID := session.SelectedAccountID

	query := paramString(params, "query")
	if query == "" {
		return errorResponse("INVALID_PARAMS", "query is required")
	}
	limit := paramIntDefault(params, "limit", 50)

	msgs, err := s.db.SearchMessages(accountID, query, limit)
	if err != nil {
		slog.Error("search messages", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to search messages")
	}

	return &ToolResponse{
		OK:      true,
		Message: "search complete",
		Data:    msgs,
	}
}
