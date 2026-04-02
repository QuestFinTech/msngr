// Package smtp provides an SMTP client adapter for sending outbound email
// with STARTTLS or implicit TLS support.
package smtp

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

// Client holds SMTP connection parameters.
type Client struct {
	host string
	port int
	tls  bool
}

// SendRequest describes an outbound email to be sent.
type SendRequest struct {
	From    string
	To      []string
	Cc      []string
	Subject string
	Text    string
	HTML    string
}

// SendResult captures the outcome of a send attempt.
type SendResult struct {
	Success      bool
	SMTPResponse string
	Error        string
}

// NewClient creates a new SMTP client configuration.
func NewClient(host string, port int, useTLS bool) *Client {
	return &Client{host: host, port: port, tls: useTLS}
}

// Send connects to the SMTP server, authenticates, and delivers the message.
func (c *Client) Send(username, password string, req *SendRequest) *SendResult {
	addr := net.JoinHostPort(c.host, fmt.Sprintf("%d", c.port))

	var smtpClient *smtp.Client
	var err error

	if c.port == 465 || (c.tls && c.port != 587) {
		// Implicit TLS (SMTPS): wrap the connection with TLS first.
		tlsConn, dialErr := tls.Dial("tcp", addr, &tls.Config{ServerName: c.host})
		if dialErr != nil {
			return &SendResult{Error: fmt.Sprintf("tls dial: %v", dialErr)}
		}
		smtpClient, err = smtp.NewClient(tlsConn, c.host)
		if err != nil {
			tlsConn.Close()
			return &SendResult{Error: fmt.Sprintf("smtp new client: %v", err)}
		}
	} else {
		// Plain or STARTTLS connection.
		conn, dialErr := net.DialTimeout("tcp", addr, 30*time.Second)
		if dialErr != nil {
			return &SendResult{Error: fmt.Sprintf("dial: %v", dialErr)}
		}
		smtpClient, err = smtp.NewClient(conn, c.host)
		if err != nil {
			conn.Close()
			return &SendResult{Error: fmt.Sprintf("smtp new client: %v", err)}
		}
		// Attempt STARTTLS if the server supports it.
		if ok, _ := smtpClient.Extension("STARTTLS"); ok {
			if err := smtpClient.StartTLS(&tls.Config{ServerName: c.host}); err != nil {
				smtpClient.Close()
				return &SendResult{Error: fmt.Sprintf("starttls: %v", err)}
			}
		}
	}
	defer smtpClient.Close()

	// Authenticate.
	auth := smtp.PlainAuth("", username, password, c.host)
	if err := smtpClient.Auth(auth); err != nil {
		return &SendResult{Error: fmt.Sprintf("auth: %v", err)}
	}

	// Set sender.
	if err := smtpClient.Mail(req.From); err != nil {
		return &SendResult{Error: fmt.Sprintf("mail from: %v", err)}
	}

	// Set recipients (To + Cc).
	allRecipients := make([]string, 0, len(req.To)+len(req.Cc))
	allRecipients = append(allRecipients, req.To...)
	allRecipients = append(allRecipients, req.Cc...)
	for _, rcpt := range allRecipients {
		if err := smtpClient.Rcpt(rcpt); err != nil {
			return &SendResult{Error: fmt.Sprintf("rcpt %s: %v", rcpt, err)}
		}
	}

	// Compose and send message data.
	wc, err := smtpClient.Data()
	if err != nil {
		return &SendResult{Error: fmt.Sprintf("data: %v", err)}
	}

	msg, err := composeMessage(req)
	if err != nil {
		wc.Close()
		return &SendResult{Error: fmt.Sprintf("compose: %v", err)}
	}

	if _, err := io.WriteString(wc, msg); err != nil {
		wc.Close()
		return &SendResult{Error: fmt.Sprintf("write: %v", err)}
	}

	if err := wc.Close(); err != nil {
		return &SendResult{Error: fmt.Sprintf("close data: %v", err)}
	}

	if err := smtpClient.Quit(); err != nil {
		// Message was likely accepted; treat as success with a note.
		return &SendResult{
			Success:      true,
			SMTPResponse: fmt.Sprintf("quit warning: %v", err),
		}
	}

	return &SendResult{Success: true, SMTPResponse: "250 OK"}
}

// composeMessage builds the full RFC 5322 message with MIME headers.
func composeMessage(req *SendRequest) (string, error) {
	var buf strings.Builder

	messageID := generateMessageID()

	// Write headers.
	writeHeader(&buf, "From", req.From)
	writeHeader(&buf, "To", strings.Join(req.To, ", "))
	if len(req.Cc) > 0 {
		writeHeader(&buf, "Cc", strings.Join(req.Cc, ", "))
	}
	writeHeader(&buf, "Subject", req.Subject)
	writeHeader(&buf, "Date", time.Now().UTC().Format(time.RFC1123Z))
	writeHeader(&buf, "Message-ID", fmt.Sprintf("<%s>", messageID))
	writeHeader(&buf, "MIME-Version", "1.0")

	if req.HTML != "" && req.Text != "" {
		// Multipart/alternative with both text and HTML.
		boundary := generateBoundary()
		writeHeader(&buf, "Content-Type", fmt.Sprintf("multipart/alternative; boundary=%q", boundary))
		buf.WriteString("\r\n")

		mw := multipart.NewWriter(&buf)
		mw.SetBoundary(boundary)

		// Text part.
		textHeader := make(textproto.MIMEHeader)
		textHeader.Set("Content-Type", "text/plain; charset=utf-8")
		textHeader.Set("Content-Transfer-Encoding", "quoted-printable")
		part, err := mw.CreatePart(textHeader)
		if err != nil {
			return "", fmt.Errorf("create text part: %w", err)
		}
		io.WriteString(part, req.Text)

		// HTML part.
		htmlHeader := make(textproto.MIMEHeader)
		htmlHeader.Set("Content-Type", "text/html; charset=utf-8")
		htmlHeader.Set("Content-Transfer-Encoding", "quoted-printable")
		part, err = mw.CreatePart(htmlHeader)
		if err != nil {
			return "", fmt.Errorf("create html part: %w", err)
		}
		io.WriteString(part, req.HTML)

		mw.Close()
	} else if req.HTML != "" {
		writeHeader(&buf, "Content-Type", "text/html; charset=utf-8")
		buf.WriteString("\r\n")
		buf.WriteString(req.HTML)
	} else {
		writeHeader(&buf, "Content-Type", "text/plain; charset=utf-8")
		buf.WriteString("\r\n")
		buf.WriteString(req.Text)
	}

	return buf.String(), nil
}

func writeHeader(buf *strings.Builder, key, value string) {
	buf.WriteString(key)
	buf.WriteString(": ")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

// generateMessageID produces a unique Message-ID value.
func generateMessageID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x@msngr",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// generateBoundary produces a random MIME boundary string.
func generateBoundary() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("msngr-%x", b)
}
