package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// retrievedFolder is the only folder MSNGR polls. Anything else can only hold messages
// that were retrieved before the folder set changed, so it is checked rather than
// silently returning nothing.
const retrievedFolder = "INBOX"

// toolListMessages lists messages for the session's selected account in a folder.
//
// An empty result and an unretrievable folder are answered differently on purpose.
// Returning nothing for both makes "no mail", "not polled yet" and "no such folder"
// indistinguishable, and each of those invites a different next action.
func (s *Server) toolListMessages(ctx context.Context, params map[string]interface{}) *ToolResponse {
	session := getSession(ctx)
	if errResp := requireAccountSelected(session); errResp != nil {
		return errResp
	}
	accountID := session.SelectedAccountID

	folder := paramStringDefault(params, "folder", retrievedFolder)
	limit := paramIntDefault(params, "limit", 50)

	acct, err := s.db.GetAccountByID(accountID)
	if err != nil {
		slog.Error("get account", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to look up account")
	}
	if acct == nil {
		return errorResponse("NOT_FOUND", "account not found")
	}

	known, err := s.db.ListRetrievedFolders(accountID)
	if err != nil {
		slog.Error("list retrieved folders", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to list folders")
	}

	if !strings.EqualFold(folder, retrievedFolder) && !containsFold(known, folder) {
		return &ToolResponse{
			OK:        false,
			ErrorCode: "FOLDER_NOT_RETRIEVED",
			Message: fmt.Sprintf("no messages have been retrieved into folder %q; MSNGR polls %s and lists locally stored messages, "+
				"so folders the gateway does not retrieve (including Sent) are always empty here", folder, retrievedFolder),
			Details: map[string]interface{}{
				"requested_folder":  folder,
				"polled_folder":     retrievedFolder,
				"available_folders": known,
			},
			Suggestion: "list " + retrievedFolder + ", or use msngr_queue_status to inspect outbound messages",
		}
	}

	msgs, err := s.db.ListMessages(accountID, folder, limit)
	if err != nil {
		slog.Error("list messages", "error", err)
		return errorResponse("INTERNAL_ERROR", "failed to list messages")
	}

	message := fmt.Sprintf("%d message(s) in %s", len(msgs), folder)
	if len(msgs) == 0 {
		message = fmt.Sprintf("folder %s holds no retrieved messages", folder)
	}

	return &ToolResponse{
		OK:      true,
		Message: message,
		Data:    msgs,
		// Retrieval state travels beside the contents, not inside them: an empty inbox
		// is only trustworthy if the caller can see when the gateway last looked.
		Details: map[string]interface{}{
			"folder":            folder,
			"count":             len(msgs),
			"limit":             limit,
			"retrieval_enabled": acct.RetrievalEnabled,
			"last_polled_at":    acct.LastPolledAt,
			"health_status":     acct.HealthStatus,
		},
	}
}

// containsFold reports whether values contains target, case-insensitively.
func containsFold(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
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
		Message: fmt.Sprintf("%d message(s) matched", len(msgs)),
		Data:    msgs,
		Details: map[string]interface{}{
			"query": query,
			"count": len(msgs),
			"limit": limit,
			"scope": "locally retrieved messages only",
		},
	}
}
