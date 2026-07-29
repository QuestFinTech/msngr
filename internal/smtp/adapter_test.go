package smtp

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeSMTPServer is a minimal SMTP server that speaks just enough of the protocol to
// accept one message, and records what it received.
type fakeSMTPServer struct {
	listener net.Listener
	host     string
	port     int

	// dataReply is the reply sent after the message body's terminating dot.
	dataReply string

	mu       sync.Mutex
	received string
	rcpts    []string
	done     chan struct{}
}

func newFakeSMTPServer(t *testing.T, dataReply string) *fakeSMTPServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	s := &fakeSMTPServer{
		listener:  ln,
		host:      "127.0.0.1",
		port:      addr.Port,
		dataReply: dataReply,
		done:      make(chan struct{}),
	}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeSMTPServer) serve() {
	defer close(s.done)
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	write := func(line string) { conn.Write([]byte(line + "\r\n")) }

	write("220 fake ESMTP ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))

		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			write("250-fake greets you")
			write("250 AUTH PLAIN")
		case strings.HasPrefix(cmd, "HELO"):
			write("250 fake")
		case strings.HasPrefix(cmd, "AUTH"):
			write("235 2.7.0 Authentication successful")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			write("250 2.1.0 Ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			s.mu.Lock()
			s.rcpts = append(s.rcpts, strings.TrimSpace(line))
			s.mu.Unlock()
			write("250 2.1.5 Ok")
		case cmd == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			var body strings.Builder
			for {
				dataLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
				body.WriteString(dataLine)
			}
			s.mu.Lock()
			s.received = body.String()
			s.mu.Unlock()
			write(s.dataReply)
		case cmd == "QUIT":
			write("221 2.0.0 Bye")
			return
		default:
			write("250 2.0.0 Ok")
		}
	}
}

func (s *fakeSMTPServer) body() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received
}

func (s *fakeSMTPServer) recipients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.rcpts...)
}

// The point of driving DATA manually is to capture the server's real reply, so that
// the audit trail records what the server actually said rather than a hardcoded 250.
func TestSendCapturesServerResponse(t *testing.T) {
	server := newFakeSMTPServer(t, "250 2.0.0 Ok: queued as ABC123")
	client := NewClient(server.host, server.port, false)

	result := client.Send("user", "pass", &SendRequest{
		From:    "sender@example.com",
		To:      []string{"rcpt@example.com"},
		Subject: "Hello",
		Text:    "body text",
	})

	if !result.Success {
		t.Fatalf("Send failed: %s", result.Error)
	}
	if result.SMTPResponse != "250 2.0.0 Ok: queued as ABC123" {
		t.Errorf("SMTPResponse = %q, want the server's verbatim reply", result.SMTPResponse)
	}
	if result.MessageID == "" {
		t.Error("MessageID is empty; the audit trail has nothing to correlate on")
	}

	body := server.body()
	if !strings.Contains(body, "Subject: Hello") {
		t.Errorf("server did not receive the subject; got:\n%s", body)
	}
	if !strings.Contains(body, "body text") {
		t.Errorf("server did not receive the body; got:\n%s", body)
	}
	if !strings.Contains(body, "<"+result.MessageID+">") {
		t.Errorf("reported MessageID %q is not the one stamped on the message:\n%s", result.MessageID, body)
	}
}

func TestSendDeliversToAllRecipients(t *testing.T) {
	server := newFakeSMTPServer(t, "250 Ok")
	client := NewClient(server.host, server.port, false)

	result := client.Send("user", "pass", &SendRequest{
		From:    "sender@example.com",
		To:      []string{"a@example.com", "b@example.com"},
		Cc:      []string{"c@example.com"},
		Subject: "Multi",
		Text:    "body",
	})
	if !result.Success {
		t.Fatalf("Send failed: %s", result.Error)
	}

	got := strings.Join(server.recipients(), " ")
	for _, want := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("recipient %s was not sent in RCPT TO; got %q", want, got)
		}
	}
}

func TestSendRejectionIsNotReportedAsSuccess(t *testing.T) {
	server := newFakeSMTPServer(t, "552 5.3.4 Message too big")
	client := NewClient(server.host, server.port, false)

	result := client.Send("user", "pass", &SendRequest{
		From:    "sender@example.com",
		To:      []string{"rcpt@example.com"},
		Subject: "Rejected",
		Text:    "body",
	})

	if result.Success {
		t.Fatal("a 552 rejection was reported as a successful send")
	}
	if result.Error == "" {
		t.Error("rejection produced no error text")
	}
}

func TestSendWithAttachmentIsMultipart(t *testing.T) {
	server := newFakeSMTPServer(t, "250 Ok")
	client := NewClient(server.host, server.port, false)

	payload := []byte("attachment payload")
	result := client.Send("user", "pass", &SendRequest{
		From:    "sender@example.com",
		To:      []string{"rcpt@example.com"},
		Subject: "With attachment",
		Text:    "see attached",
		Attachments: []SendAttachment{{
			Filename:      "note.txt",
			MimeType:      "text/plain",
			ContentBase64: base64.StdEncoding.EncodeToString(payload),
		}},
	})
	if !result.Success {
		t.Fatalf("Send failed: %s", result.Error)
	}

	body := server.body()
	if !strings.Contains(body, "multipart/mixed") {
		t.Errorf("attachment did not produce a multipart/mixed message:\n%s", body)
	}
	if !strings.Contains(body, `filename="note.txt"`) {
		t.Errorf("attachment filename missing:\n%s", body)
	}
	if !strings.Contains(body, base64.StdEncoding.EncodeToString(payload)) {
		t.Errorf("attachment content missing:\n%s", body)
	}
}

// A line consisting of a single dot must be escaped, or it terminates the message
// early and the remainder is interpreted as SMTP commands.
func TestSendEscapesLeadingDot(t *testing.T) {
	server := newFakeSMTPServer(t, "250 Ok")
	client := NewClient(server.host, server.port, false)

	result := client.Send("user", "pass", &SendRequest{
		From:    "sender@example.com",
		To:      []string{"rcpt@example.com"},
		Subject: "Dotted",
		Text:    "first line\r\n.\r\nlast line",
	})
	if !result.Success {
		t.Fatalf("Send failed: %s", result.Error)
	}

	body := server.body()
	if !strings.Contains(body, "last line") {
		t.Errorf("message was truncated at a bare dot line; got:\n%s", body)
	}
}
