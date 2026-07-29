package secret

import (
	"strings"
	"testing"
)

func newTestCrypter(t *testing.T, key string) *Crypter {
	t.Helper()
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	c, err := NewCrypter(key, salt)
	if err != nil {
		t.Fatalf("NewCrypter: %v", err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := newTestCrypter(t, "correct horse battery staple")

	for _, plaintext := range []string{"", "hunter2", "pässwörd with späces", strings.Repeat("x", 4096)} {
		sealed, err := c.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plaintext, err)
		}
		if !IsCiphertext(sealed) {
			t.Errorf("Encrypt(%q) produced a value IsCiphertext does not recognise: %q", plaintext, sealed)
		}
		if plaintext != "" && strings.Contains(sealed, plaintext) {
			t.Errorf("Encrypt(%q) leaked the plaintext into %q", plaintext, sealed)
		}

		got, err := c.Decrypt(sealed)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got != plaintext {
			t.Errorf("round trip = %q, want %q", got, plaintext)
		}
	}
}

func TestEncryptIsNondeterministic(t *testing.T) {
	c := newTestCrypter(t, "key")

	first, err := c.Encrypt("same value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	second, err := c.Encrypt("same value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if first == second {
		t.Error("encrypting the same value twice produced identical ciphertext; the nonce is not random")
	}
}

// Legacy cleartext must survive enabling encryption, or turning it on locks a running
// deployment out of its own mail accounts.
func TestDecryptPassesThroughLegacyPlaintext(t *testing.T) {
	c := newTestCrypter(t, "key")

	got, err := c.Decrypt("legacy-cleartext-password")
	if err != nil {
		t.Fatalf("Decrypt legacy value: %v", err)
	}
	if got != "legacy-cleartext-password" {
		t.Errorf("Decrypt legacy value = %q, want it returned unchanged", got)
	}
	if IsCiphertext("legacy-cleartext-password") {
		t.Error("IsCiphertext reported a cleartext value as encrypted")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	right, err := NewCrypter("the right key", salt)
	if err != nil {
		t.Fatalf("NewCrypter: %v", err)
	}
	wrong, err := NewCrypter("the wrong key", salt)
	if err != nil {
		t.Fatalf("NewCrypter: %v", err)
	}

	sealed, err := right.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := wrong.Decrypt(sealed); err == nil {
		t.Fatal("decrypting with the wrong key succeeded; GCM authentication is not being enforced")
	}
}

func TestSameKeyDifferentSaltDiffers(t *testing.T) {
	saltA, _ := NewSalt()
	saltB, _ := NewSalt()
	a, err := NewCrypter("shared passphrase", saltA)
	if err != nil {
		t.Fatalf("NewCrypter: %v", err)
	}
	b, err := NewCrypter("shared passphrase", saltB)
	if err != nil {
		t.Fatalf("NewCrypter: %v", err)
	}

	sealed, err := a.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := b.Decrypt(sealed); err == nil {
		t.Error("two deployments sharing a passphrase derived the same key; the salt is not being used")
	}
}

func TestNewCrypterRejectsBadInput(t *testing.T) {
	salt, _ := NewSalt()
	if _, err := NewCrypter("", salt); err == nil {
		t.Error("NewCrypter accepted an empty key")
	}
	if _, err := NewCrypter("key", []byte("too short")); err == nil {
		t.Error("NewCrypter accepted a salt of the wrong length")
	}
}
