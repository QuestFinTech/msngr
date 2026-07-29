package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/luxemque/msngr/internal/model"
)

// sessionSecretKey is the system_settings key holding the cookie signing secret.
const sessionSecretKey = "operator_session_secret"

// sessionCookieValue is "<operator id>.<email>.<issued at unix>.<signature>".
//
// The signature covers the other three fields. Before it existed the cookie was just
// "id:email", which any visitor could type: the server looked the ID up and compared
// the email to what the cookie itself claimed, so a forged cookie authenticated as any
// operator whose address you could guess.
const sessionFieldSep = "."

// sessionSecret returns the HMAC key for operator cookies, generating and storing one
// on first use. The secret lives in the database so sessions survive a restart.
func (s *Server) sessionSecret() ([]byte, error) {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()

	if s.cachedSecret != nil {
		return s.cachedSecret, nil
	}

	stored, err := s.db.GetSystemSetting(sessionSecretKey)
	if err != nil {
		return nil, fmt.Errorf("read session secret: %w", err)
	}
	if stored != "" {
		secret, err := base64.StdEncoding.DecodeString(stored)
		if err != nil {
			return nil, fmt.Errorf("decode session secret: %w", err)
		}
		if len(secret) >= 32 {
			s.cachedSecret = secret
			return secret, nil
		}
		// Too short to trust; fall through and mint a new one.
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate session secret: %w", err)
	}
	if err := s.db.SetSystemSetting(sessionSecretKey, base64.StdEncoding.EncodeToString(secret)); err != nil {
		return nil, fmt.Errorf("store session secret: %w", err)
	}
	s.cachedSecret = secret
	return secret, nil
}

// signSession returns the signature for a cookie payload.
func signSession(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// newSessionValue builds a signed cookie value for an operator.
func (s *Server) newSessionValue(op *model.Operator) (string, error) {
	secret, err := s.sessionSecret()
	if err != nil {
		return "", err
	}
	// The address is base64url-encoded so no field can contain the separator —
	// every real address contains dots, and a naive split would mangle them.
	payload := strings.Join([]string{
		strconv.FormatInt(op.ID, 10),
		base64.RawURLEncoding.EncodeToString([]byte(op.Email)),
		strconv.FormatInt(time.Now().UTC().Unix(), 10),
	}, sessionFieldSep)
	return payload + sessionFieldSep + signSession(secret, payload), nil
}

// parseSessionValue verifies a cookie value and returns the operator ID and email it
// attests to. The signature is checked before anything in the cookie is trusted, and
// expiry is enforced server-side rather than relying on the browser to drop the cookie.
func (s *Server) parseSessionValue(value string) (int64, string, bool) {
	idx := strings.LastIndex(value, sessionFieldSep)
	if idx < 0 {
		return 0, "", false
	}
	payload, signature := value[:idx], value[idx+1:]

	secret, err := s.sessionSecret()
	if err != nil {
		slog.Error("session secret unavailable", "error", err)
		return 0, "", false
	}
	expected := signSession(secret, payload)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return 0, "", false
	}

	parts := strings.Split(payload, sessionFieldSep)
	if len(parts) != 3 {
		return 0, "", false
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", false
	}
	email, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, "", false
	}
	issuedAt, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return 0, "", false
	}
	if time.Since(time.Unix(issuedAt, 0)) > time.Duration(s.operatorSessionMinutes)*time.Minute {
		return 0, "", false
	}
	return id, string(email), true
}

// currentOperator returns the operator the request's cookie authenticates, or nil.
func (s *Server) currentOperator(r *http.Request) *model.Operator {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}

	id, email, ok := s.parseSessionValue(c.Value)
	if !ok {
		return nil
	}

	op, err := s.db.GetOperatorByID(id)
	if err != nil || op == nil {
		return nil
	}
	// The address is re-checked against the stored record so a cookie issued before an
	// address change stops working.
	if op.Email != email {
		return nil
	}
	return op
}

func (s *Server) setSession(w http.ResponseWriter, op *model.Operator) {
	value, err := s.newSessionValue(op)
	if err != nil {
		slog.Error("could not create session cookie", "error", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   s.operatorSessionMinutes * 60,
	})
}

func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}
