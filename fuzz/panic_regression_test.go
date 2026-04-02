package fuzz

// Regression tests for panic bugs found during audit.
// Each test targets a specific code path that previously panicked on malformed input.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// TestPanicJWSVerifyEmptySignatures tests that Verify on a JWS with no
// signatures returns an error instead of panicking (signing.go:406).
func TestPanicJWSVerifyEmptySignatures(t *testing.T) {
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	jws := jose.JSONWebSignature{}
	_, err := jws.Verify(hmacKey)
	if err == nil {
		t.Fatal("expected error for empty signatures")
	}
}

// TestPanicJWSDetachedVerifyEmptySignatures tests that DetachedVerify
// on a JWS with no signatures returns an error (signing.go:406).
func TestPanicJWSDetachedVerifyEmptySignatures(t *testing.T) {
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	jws := jose.JSONWebSignature{}
	err := jws.DetachedVerify([]byte("payload"), hmacKey)
	if err == nil {
		t.Fatal("expected error for empty signatures")
	}
}

// TestPanicJWSCompactSerializeEmptySignatures tests that CompactSerialize
// on a JWS with no signatures returns an error (jws.go:414).
func TestPanicJWSCompactSerializeEmptySignatures(t *testing.T) {
	jws := jose.JSONWebSignature{}
	_, err := jws.CompactSerialize()
	if err == nil {
		t.Fatal("expected error for empty signatures")
	}
}

// TestPanicJWSDetachedCompactSerializeEmptySignatures tests that
// DetachedCompactSerialize on a JWS with no signatures returns an error.
func TestPanicJWSDetachedCompactSerializeEmptySignatures(t *testing.T) {
	jws := jose.JSONWebSignature{}
	_, err := jws.DetachedCompactSerialize()
	if err == nil {
		t.Fatal("expected error for empty signatures")
	}
}

// TestPanicJWEDecryptEmptyRecipients tests that Decrypt on a JWE with no
// recipients returns an error instead of panicking (crypter.go:489).
func TestPanicJWEDecryptEmptyRecipients(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	jwe := jose.JSONWebEncryption{}
	_, err := jwe.Decrypt(rsaKey)
	if err == nil {
		t.Fatal("expected error for empty recipients")
	}
}

// TestPanicJWECompactSerializeEmptyRecipients tests that CompactSerialize
// on a JWE with no recipients returns an error (jwe.go:345).
func TestPanicJWECompactSerializeEmptyRecipients(t *testing.T) {
	jwe := jose.JSONWebEncryption{}
	_, err := jwe.CompactSerialize()
	if err == nil {
		t.Fatal("expected error for empty recipients")
	}
}

// TestPanicJWEFullSerializeEmptyRecipients tests that FullSerialize
// on a JWE with no recipients returns empty string (jwe.go:366).
func TestPanicJWEFullSerializeEmptyRecipients(t *testing.T) {
	jwe := jose.JSONWebEncryption{}
	result := jwe.FullSerialize()
	if result != "" {
		t.Fatalf("expected empty string for empty recipients, got %q", result)
	}
}

// TestPanicJWKThumbprintShortEd25519 tests that Thumbprint on a JWK
// with a short ed25519 private key returns an error (jwk.go:415).
func TestPanicJWKThumbprintShortEd25519(t *testing.T) {
	shortKey := ed25519.PrivateKey([]byte("too short"))
	jwk := jose.JSONWebKey{Key: shortKey}
	_, err := jwk.Thumbprint(4) // crypto.SHA256 = 4
	if err == nil {
		t.Fatal("expected error for short ed25519 key")
	}
}

// TestPanicJWKMarshalShortEd25519 tests that MarshalJSON on a JWK
// with a short ed25519 private key returns an error (jwk.go:672).
func TestPanicJWKMarshalShortEd25519(t *testing.T) {
	shortKey := ed25519.PrivateKey([]byte("too short"))
	jwk := jose.JSONWebKey{Key: shortKey}
	_, err := jwk.MarshalJSON()
	if err == nil {
		t.Fatal("expected error for short ed25519 key")
	}
}

// TestPanicKeyUnwrapEmpty tests that KeyUnwrap with empty ciphertext
// returns an error instead of panicking (cipher/key_wrap.go:75).
func TestPanicKeyUnwrapEmpty(t *testing.T) {
	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	// Empty encrypted_key with A128KW algorithm
	input := "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA"
	parsed, err := jose.ParseEncrypted(input,
		[]jose.KeyAlgorithm{jose.A128KW},
		[]jose.ContentEncryption{jose.A128CBC_HS256},
	)
	if err != nil {
		t.Skipf("parse error: %v", err)
	}
	_, err = parsed.Decrypt(aesKey)
	if err == nil {
		t.Fatal("expected error for empty encrypted key")
	}
}
