package queue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	imapAdapter "github.com/luxemque/msngr/internal/imap"
	"github.com/luxemque/msngr/internal/model"
	smtpAdapter "github.com/luxemque/msngr/internal/smtp"
	"github.com/luxemque/msngr/internal/storage"
)

// sentFolderFallback is the folder name recorded when the server exposes no Sent
// mailbox. The metadata row still says where the message would live.
const sentFolderFallback = "Sent"

// sentCopy describes a delivered message that needs to be filed.
type sentCopy struct {
	account   *model.Account
	item      model.OutboundItem
	to        []string
	cc        []string
	messageID string
	raw       string
	atts      []smtpAdapter.SendAttachment
}

// recordSentCopy retains a copy of a message the gateway has delivered.
//
// SMTP leaves nothing behind on the sender's side: without this the gateway keeps a
// record that it sent something but not what it sent, so after the fact there is no
// body, no recipient list and no timestamp to consult. Inbound mail has been archived
// this way all along; this makes outbound symmetric.
//
// Every step is best-effort. The message has already been accepted by the server, and
// failing to file a copy must not turn a delivered message into a failed one.
func (p *Processor) recordSentCopy(ctx context.Context, logger *slog.Logger, c sentCopy) {
	archivePath, contentHash := p.archiveSentMessage(logger, c)

	folder := sentFolderFallback
	if appended, err := p.appendToSentFolder(logger, c); err != nil {
		logger.Error("Failed to file message in Sent folder", "error", err)
	} else if appended != "" {
		folder = appended
	}

	toJSON, _ := json.Marshal(c.to)
	ccJSON, _ := json.Marshal(c.cc)

	msg := &model.Message{
		AccountID:    c.account.ID,
		MessageID:    "<" + c.messageID + ">",
		Folder:       folder,
		FromAddr:     c.item.FromAddr,
		ToAddrs:      string(toJSON),
		CcAddrs:      string(ccJSON),
		Subject:      c.item.Subject,
		Date:         nowRFC3339(),
		Size:         int64(len(c.raw)),
		ContentHash:  contentHash,
		Direction:    "outbound",
		ArchivePath:  archivePath,
		StoredOnDisk: archivePath != "",
		IsRead:       true,
	}
	if _, err := p.db.InsertMessage(msg); err != nil {
		// A message sent to one of the gateway's own accounts can collide on the
		// (account_id, message_id) uniqueness constraint once it is also retrieved.
		logger.Error("Failed to record sent message", "error", err, "message_id", msg.MessageID)
		return
	}
	logger.Info("Recorded sent message", "folder", folder, "stored_on_disk", msg.StoredOnDisk)
}

// archiveSentMessage writes the message body and attachments to filesystem storage,
// honouring the account's storage mode. It returns the archive path and content hash,
// both empty when nothing was stored.
func (p *Processor) archiveSentMessage(logger *slog.Logger, c sentCopy) (archivePath, contentHash string) {
	if p.store == nil {
		return "", ""
	}
	// Respect the operator's data-handling choice: an account set to keep metadata
	// only should not accumulate outbound bodies on disk.
	if c.account.StorageMode != "body" && c.account.StorageMode != "full" {
		return "", ""
	}

	content := &storage.MessageContent{
		BodyText: c.item.BodyText,
		BodyHTML: c.item.BodyHTML,
	}
	if c.account.StorageMode == "full" {
		for _, att := range c.atts {
			data, err := base64.StdEncoding.DecodeString(att.ContentBase64)
			if err != nil {
				logger.Error("Failed to decode attachment for archive", "filename", att.Filename, "error", err)
				continue
			}
			content.Attachments = append(content.Attachments, storage.AttachmentContent{
				Filename: att.Filename,
				Data:     data,
			})
		}
	}
	if content.BodyText == "" && content.BodyHTML == "" && len(content.Attachments) == 0 {
		return "", ""
	}

	path, err := p.store.WriteMessage(c.account.EmailAddress, c.messageID, content)
	if err != nil {
		logger.Error("Failed to archive sent message", "error", err)
		return "", ""
	}
	return path, storage.ContentHash(content)
}

// appendToSentFolder copies the raw message into the account's Sent mailbox over IMAP,
// returning the folder it used, or "" when the server exposes none.
func (p *Processor) appendToSentFolder(logger *slog.Logger, c sentCopy) (string, error) {
	if c.account.IMAPHost == "" {
		return "", nil
	}

	username, password, err := p.db.GetAccountCredentials(c.account.ID)
	if err != nil {
		return "", fmt.Errorf("load credentials: %w", err)
	}

	client, err := imapAdapter.Connect(c.account.IMAPHost, c.account.IMAPPort, c.account.IMAPTLS)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	if err := client.Login(username, password); err != nil {
		return "", fmt.Errorf("login: %w", err)
	}

	folder, err := client.FindSentFolder()
	if err != nil {
		return "", fmt.Errorf("find sent folder: %w", err)
	}
	if folder == "" {
		logger.Warn("Server exposes no Sent folder; keeping the local copy only")
		return "", nil
	}

	if err := client.AppendMessage(folder, []byte(c.raw)); err != nil {
		return "", err
	}
	return folder, nil
}
