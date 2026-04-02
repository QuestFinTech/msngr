// Package imap provides an IMAP client adapter and polling loop for retrieving
// messages from mail servers.
package imap

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// MessageEnvelope holds metadata for a fetched message.
type MessageEnvelope struct {
	UID         uint32
	UIDValidity uint32
	MessageID   string
	From        string
	To          []string
	Cc          []string
	Subject     string
	Date        time.Time
	Size        int64
	Flags       []string
}

// AttachmentMeta holds metadata for a message attachment.
type AttachmentMeta struct {
	Filename string
	MimeType string
	Size     int64
}

// Client wraps an IMAP connection and provides high-level operations.
type Client struct {
	inner       *imapclient.Client
	uidValidity uint32
}

// Connect dials an IMAP server with TLS or STARTTLS.
func Connect(host string, port int, tls bool) (*Client, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	slog.Info("imap: connecting", "host", host, "port", port, "tls", tls)

	var (
		c   *imapclient.Client
		err error
	)
	if tls {
		c, err = imapclient.DialTLS(addr, nil)
	} else {
		c, err = imapclient.DialStartTLS(addr, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("imap connect %s: %w", addr, err)
	}

	return &Client{inner: c}, nil
}

// Login authenticates with the IMAP server.
func (c *Client) Login(username, password string) error {
	if err := c.inner.Login(username, password).Wait(); err != nil {
		return fmt.Errorf("imap login: %w", err)
	}
	slog.Info("imap: logged in", "user", username)
	return nil
}

// SelectFolder selects a mailbox and stores its UIDValidity.
func (c *Client) SelectFolder(name string) error {
	data, err := c.inner.Select(name, nil).Wait()
	if err != nil {
		return fmt.Errorf("imap select %s: %w", name, err)
	}
	c.uidValidity = data.UIDValidity
	slog.Info("imap: selected folder", "folder", name, "uidvalidity", data.UIDValidity, "messages", data.NumMessages)
	return nil
}

// FetchMessages fetches envelope metadata for messages with an internal date
// on or after the given time. It uses UID SEARCH + UID FETCH so that results
// are stable across sessions.
func (c *Client) FetchMessages(since time.Time) ([]MessageEnvelope, error) {
	// Search for messages since the given date.
	criteria := &imap.SearchCriteria{
		Since: since,
	}
	searchData, err := c.inner.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("imap uid search: %w", err)
	}

	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil, nil
	}

	uidSet := imap.UIDSetNum(uids...)

	fetchOpts := &imap.FetchOptions{
		Envelope:    true,
		Flags:       true,
		RFC822Size:  true,
		UID:         true,
	}

	fetchCmd := c.inner.Fetch(uidSet, fetchOpts)
	defer fetchCmd.Close()

	msgs, err := fetchCmd.Collect()
	if err != nil {
		return nil, fmt.Errorf("imap fetch envelopes: %w", err)
	}

	var envelopes []MessageEnvelope
	for _, buf := range msgs {
		env := MessageEnvelope{
			UID:         uint32(buf.UID),
			UIDValidity: c.uidValidity,
			Size:        buf.RFC822Size,
		}

		if buf.Envelope != nil {
			env.MessageID = buf.Envelope.MessageID
			env.Subject = buf.Envelope.Subject
			env.Date = buf.Envelope.Date

			if len(buf.Envelope.From) > 0 {
				env.From = buf.Envelope.From[0].Addr()
			}
			for _, a := range buf.Envelope.To {
				if addr := a.Addr(); addr != "" {
					env.To = append(env.To, addr)
				}
			}
			for _, a := range buf.Envelope.Cc {
				if addr := a.Addr(); addr != "" {
					env.Cc = append(env.Cc, addr)
				}
			}
		}

		for _, f := range buf.Flags {
			env.Flags = append(env.Flags, string(f))
		}

		envelopes = append(envelopes, env)
	}

	slog.Info("imap: fetched envelopes", "count", len(envelopes), "since", since.Format(time.RFC3339))
	return envelopes, nil
}

// FetchBody fetches the text/plain and text/html body parts for the given UID.
// Returns (textBody, htmlBody, error).
func (c *Client) FetchBody(uid uint32) (string, string, error) {
	uidSet := imap.UIDSetNum(imap.UID(uid))

	// First fetch body structure to find the right parts.
	structOpts := &imap.FetchOptions{
		UID: true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	}

	structCmd := c.inner.Fetch(uidSet, structOpts)
	structMsgs, err := structCmd.Collect()
	if err != nil {
		return "", "", fmt.Errorf("imap fetch bodystructure uid=%d: %w", uid, err)
	}
	if len(structMsgs) == 0 {
		return "", "", fmt.Errorf("imap fetch bodystructure uid=%d: no message found", uid)
	}

	bs := structMsgs[0].BodyStructure
	if bs == nil {
		return "", "", fmt.Errorf("imap fetch bodystructure uid=%d: nil body structure", uid)
	}

	// Walk the structure and find text/plain and text/html part paths.
	var textPath, htmlPath []int
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true // continue into multipart children
		}
		mt := sp.MediaType()
		switch {
		case mt == "text/plain" && textPath == nil:
			textPath = make([]int, len(path))
			copy(textPath, path)
		case mt == "text/html" && htmlPath == nil:
			htmlPath = make([]int, len(path))
			copy(htmlPath, path)
		}
		return true
	})

	// Build fetch options for the body sections we found.
	fetchOpts := &imap.FetchOptions{UID: true}

	var textSection, htmlSection *imap.FetchItemBodySection
	if textPath != nil {
		textSection = &imap.FetchItemBodySection{
			Part:      textPath,
			Specifier: imap.PartSpecifierNone,
			Peek:      true,
		}
		fetchOpts.BodySection = append(fetchOpts.BodySection, textSection)
	}
	if htmlPath != nil {
		htmlSection = &imap.FetchItemBodySection{
			Part:      htmlPath,
			Specifier: imap.PartSpecifierNone,
			Peek:      true,
		}
		fetchOpts.BodySection = append(fetchOpts.BodySection, htmlSection)
	}

	if len(fetchOpts.BodySection) == 0 {
		// No text parts found.
		return "", "", nil
	}

	bodyCmd := c.inner.Fetch(uidSet, fetchOpts)
	bodyMsgs, err := bodyCmd.Collect()
	if err != nil {
		return "", "", fmt.Errorf("imap fetch body uid=%d: %w", uid, err)
	}
	if len(bodyMsgs) == 0 {
		return "", "", nil
	}

	var textBody, htmlBody string
	for _, sec := range bodyMsgs[0].BodySection {
		mt := partMediaType(bs, sec.Section.Part)
		switch mt {
		case "text/plain":
			textBody = string(sec.Bytes)
		case "text/html":
			htmlBody = string(sec.Bytes)
		}
	}

	return textBody, htmlBody, nil
}

// partMediaType resolves the media type of a part given its path in the body structure.
func partMediaType(bs imap.BodyStructure, path []int) string {
	var result string
	bs.Walk(func(p []int, part imap.BodyStructure) bool {
		if intSliceEqual(p, path) {
			if sp, ok := part.(*imap.BodyStructureSinglePart); ok {
				result = sp.MediaType()
			}
		}
		return true
	})
	return result
}

func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FetchAttachments returns metadata for attachments on the given UID.
// It examines the BODYSTRUCTURE for parts with a "attachment" disposition
// or non-text/non-multipart parts with a filename.
func (c *Client) FetchAttachments(uid uint32) ([]AttachmentMeta, error) {
	uidSet := imap.UIDSetNum(imap.UID(uid))

	fetchOpts := &imap.FetchOptions{
		UID:           true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	}

	fetchCmd := c.inner.Fetch(uidSet, fetchOpts)
	msgs, err := fetchCmd.Collect()
	if err != nil {
		return nil, fmt.Errorf("imap fetch bodystructure uid=%d: %w", uid, err)
	}
	if len(msgs) == 0 {
		return nil, nil
	}

	bs := msgs[0].BodyStructure
	if bs == nil {
		return nil, nil
	}

	var attachments []AttachmentMeta
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true
		}

		disp := sp.Disposition()
		isAttachment := disp != nil && strings.EqualFold(disp.Value, "attachment")
		filename := sp.Filename()

		// Also treat inline parts with a filename as attachments (common pattern).
		if !isAttachment && filename == "" {
			return true
		}

		attachments = append(attachments, AttachmentMeta{
			Filename: filename,
			MimeType: sp.MediaType(),
			Size:     int64(sp.Size),
		})
		return true
	})

	return attachments, nil
}

// Close logs out and closes the underlying connection.
func (c *Client) Close() error {
	if c.inner == nil {
		return nil
	}
	err := c.inner.Logout().Wait()
	closeErr := c.inner.Close()
	if err != nil {
		return fmt.Errorf("imap logout: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("imap close: %w", closeErr)
	}
	slog.Info("imap: connection closed")
	return nil
}
