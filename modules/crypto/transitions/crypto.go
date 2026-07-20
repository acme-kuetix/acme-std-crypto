package transitions

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/kuetix/engine/engine/domain"
	"github.com/kuetix/engine/engine/domain/interfaces"
	"github.com/kuetix/engine/engine/workflow"
	"golang.org/x/crypto/bcrypt"
)

// PROMOTION-CANDIDATE: stable since Wave 9-17, no acme-* deps, used in 4 packages.
// Provides bcrypt Hash/Compare, HMAC Sign/Verify, JWT issue/verify delegation.
// No std-* equivalent (std-auth is JWT-only, not bcrypt/HMAC). Consider
// promoting to std-crypto after kuetix review.

// cryptoTransitions exposes WSL-callable cryptographic primitives:
// password hashing (bcrypt), HMAC signing (for webhook payloads), and
// JWT issue/verify (delegated to std-auth). These are extracted from
// acme-auth and acme-webhook so the crypto implementation is shared
// across packages instead of duplicated.
//
// Package-level helpers (HashVal, CompareVal, SignVal, VerifyVal) are
// also exported so acme-* packages can call them directly from Go
// without going through the WSL engine.
type cryptoTransitions struct {
	workflow.BaseServiceTransition
}

// NewCryptoTransitions returns a new cryptoTransitions instance.
func NewCryptoTransitions() interfaces.ServiceTransitions {
	return &cryptoTransitions{}
}

// ──────────────────────────────────────────────────────────────
// Password hashing (bcrypt)
// ──────────────────────────────────────────────────────────────

// Hash bcrypt-hashes a password using the default cost (10).
// Returns {hash: string} on success.
// WSL: crypto/crypto.Hash(value: $json.password)
func (t *cryptoTransitions) Hash(value string) (r domain.FlowStepResult) {
	if value == "" {
		r.Success = false
		r.StatusCode = 400
		r.Error = fmt.Errorf("password is required")
		r.Response = map[string]interface{}{"code": "invalid_password", "message": "password is required"}
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	if err != nil {
		r.Success = false
		r.StatusCode = 500
		r.Error = fmt.Errorf("hash failed: %v", err)
		r.Response = map[string]interface{}{"code": "hash_failed", "message": "could not hash password"}
		return
	}
	r.Success = true
	r.StatusCode = 200
	r.Response = map[string]interface{}{"hash": string(hash)}
	return
}

// Compare verifies a password against a bcrypt hash. Returns {valid: bool}.
// WSL: crypto/crypto.Compare(value: $json.password, hash: $user.passwordHash)
func (t *cryptoTransitions) Compare(value, hash string) (r domain.FlowStepResult) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(value))
	r.Success = true
	r.StatusCode = 200
	r.Response = map[string]interface{}{"valid": err == nil}
	return
}

// ──────────────────────────────────────────────────────────────
// HMAC signing (for webhook payloads)
// ──────────────────────────────────────────────────────────────
// Package-level helpers (callable from Go without WSL engine)
// ──────────────────────────────────────────────────────────────

// HashVal bcrypt-hashes a password. Package-level func for Go callers.
func HashVal(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// SignVal returns the HMAC-SHA256 hex digest of message using secret.
func SignVal(secret, message string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
