// Package secret provides authenticated encryption for values that must not sit in
// the database in cleartext — currently the IMAP/SMTP credentials for mail accounts.
//
// The stored form is "msngr1:" + base64(nonce || AES-256-GCM ciphertext). The prefix
// is a version marker: it lets a read distinguish a value this package wrote from a
// legacy cleartext value written before encryption existed, so an existing deployment
// keeps working while its rows are migrated.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// prefix marks a value as ciphertext written by this package, version 1.
const prefix = "msngr1:"

// scrypt parameters. These are deliberately expensive: the encryption key comes from
// deployment configuration and may be a human-chosen passphrase rather than 32 random
// bytes. Derivation happens once at startup, so the cost is paid on boot, not per read.
const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
	keyLen  = 32
)

// SaltLen is the length of the per-deployment KDF salt.
const SaltLen = 16

// Crypter encrypts and decrypts credential values.
type Crypter struct {
	aead cipher.AEAD
}

// NewCrypter derives an AES-256-GCM key from the configured encryption key and the
// deployment's salt. The salt is not secret; it exists so two deployments sharing a
// passphrase do not share a derived key.
func NewCrypter(key string, salt []byte) (*Crypter, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("encryption key is empty")
	}
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("salt must be %d bytes, got %d", SaltLen, len(salt))
	}

	derived, err := scrypt.Key([]byte(key), salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return &Crypter{aead: aead}, nil
}

// NewSalt generates a fresh random KDF salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// Encrypt returns the stored form of a plaintext value.
func (c *Crypter) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt returns the plaintext for a stored value.
//
// A value without the version prefix is legacy cleartext and is returned unchanged:
// enabling encryption must not lock a deployment out of its own mail accounts. Callers
// that care can detect this with IsCiphertext and re-encrypt.
func (c *Crypter) Decrypt(stored string) (string, error) {
	if !IsCiphertext(stored) {
		return stored, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, prefix))
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext shorter than nonce")
	}
	plaintext, err := c.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		// Authentication failure here almost always means the encryption key changed,
		// not that the data is corrupt. Say so — the alternative is an operator
		// debugging "cipher: message authentication failed" against a mail server.
		return "", fmt.Errorf("decrypt credential: %w (is MSNGR_ENCRYPTION_KEY the same key the value was encrypted with?)", err)
	}
	return string(plaintext), nil
}

// IsCiphertext reports whether a stored value is in this package's encrypted form.
func IsCiphertext(stored string) bool {
	return strings.HasPrefix(stored, prefix)
}
