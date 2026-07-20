package transitions

import (
	"strings"
	"testing"
)

func TestCryptoHash(t *testing.T) {
	tr := &cryptoTransitions{}

	r := tr.Hash("hunter2")
	if !r.Success {
		t.Fatalf("expected success, got: %v", r.Error)
	}
	hash, ok := r.Response.(map[string]interface{})["hash"].(string)
	if !ok || hash == "" {
		t.Fatalf("expected non-empty hash, got: %v", r.Response)
	}
	if !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("expected bcrypt prefix $2a$, got %q", hash[:4])
	}

	r = tr.Hash("")
	if r.Success {
		t.Error("expected failure for empty password")
	}
	if r.StatusCode != 400 {
		t.Errorf("status = %d, want 400", r.StatusCode)
	}
	resp, _ := r.Response.(map[string]interface{})
	if resp["code"] != "invalid_password" {
		t.Errorf("code = %v, want invalid_password", resp["code"])
	}
}

func TestCryptoCompare(t *testing.T) {
	tr := &cryptoTransitions{}

	hashR := tr.Hash("secret123")
	if !hashR.Success {
		t.Fatalf("hash failed: %v", hashR.Error)
	}
	hash := hashR.Response.(map[string]interface{})["hash"].(string)

	r := tr.Compare("secret123", hash)
	if !r.Success {
		t.Fatalf("expected success, got: %v", r.Error)
	}
	if !r.Response.(map[string]interface{})["valid"].(bool) {
		t.Error("expected valid=true for matching password")
	}

	r = tr.Compare("wrong-password", hash)
	if !r.Success {
		t.Fatalf("expected success (always returns), got: %v", r.Error)
	}
	if r.Response.(map[string]interface{})["valid"].(bool) {
		t.Error("expected valid=false for non-matching password")
	}
}

func TestCryptoPackageHelpers(t *testing.T) {
	hash, err := HashVal("password123")
	if err != nil {
		t.Fatalf("HashVal failed: %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("expected bcrypt prefix, got %q", hash[:4])
	}

	sig := SignVal("secret", "message")
	if len(sig) != 64 {
		t.Errorf("sig length = %d, want 64", len(sig))
	}
}
