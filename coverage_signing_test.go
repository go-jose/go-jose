/*-
 * Copyright 2024 go-jose authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"testing"
)

var covHMACKey1 = []byte("0123456789abcdef0123456789abcdef")
var covHMACKey2 = []byte("fedcba9876543210fedcba9876543210")

func covSignHS256(t *testing.T, payload []byte) *JSONWebSignature {
	t.Helper()
	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: covHMACKey1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestUnsafePayloadWithoutVerification(t *testing.T) {
	obj := covSignHS256(t, []byte("payload"))
	if got := string(obj.UnsafePayloadWithoutVerification()); got != "payload" {
		t.Errorf("UnsafePayloadWithoutVerification = %q, want payload", got)
	}
}

func TestDetachedVerifyErrorBranches(t *testing.T) {
	obj := covSignHS256(t, []byte("payload"))

	// Unsupported verification key type -> newVerifier default branch
	if err := obj.DetachedVerify([]byte("payload"), "not-a-key"); err == nil {
		t.Error("DetachedVerify with bad key type: expected error")
	}

	// Wrong key -> ErrCryptoFailure
	if err := obj.DetachedVerify([]byte("payload"), covHMACKey2); err == nil {
		t.Error("DetachedVerify with wrong key: expected error")
	}

	// crit in the (integrity-unprotected) per-signature header -> checkNoCritical
	critUnprotected := `{"payload":"cGF5bG9hZA",` +
		`"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"crit":["x"]},"signature":"AAAA"}`
	obj2, err := ParseSigned(critUnprotected, []SignatureAlgorithm{HS256})
	if err != nil {
		t.Fatalf("parse crit-unprotected: %v", err)
	}
	if err := obj2.DetachedVerify([]byte("payload"), covHMACKey1); err == nil {
		t.Error("DetachedVerify with crit in unprotected header: expected error")
	}

	// Unsupported crit in the protected header -> checkSupportedCritical
	critProtected := `{"payload":"cGF5bG9hZA",` +
		`"protected":"eyJhbGciOiJIUzI1NiIsImNyaXQiOlsieCJdfQ","signature":"AAAA"}`
	obj3, err := ParseSigned(critProtected, []SignatureAlgorithm{HS256})
	if err != nil {
		t.Fatalf("parse crit-protected: %v", err)
	}
	if err := obj3.DetachedVerify([]byte("payload"), covHMACKey1); err == nil {
		t.Error("DetachedVerify with unsupported protected crit: expected error")
	}

	// More than one signature -> "too many signatures"
	multi := `{"payload":"cGF5bG9hZA","signatures":[` +
		`{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"AAAA"},` +
		`{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"BBBB"}]}`
	objMulti, err := ParseSigned(multi, []SignatureAlgorithm{HS256})
	if err != nil {
		t.Fatalf("parse multi: %v", err)
	}
	if err := objMulti.DetachedVerify([]byte("payload"), covHMACKey1); err == nil {
		t.Error("DetachedVerify with multiple signatures: expected error")
	}
}

func TestVerifyMultiBranches(t *testing.T) {
	// Two real signatures under different keys.
	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: HS256, Key: covHMACKey1},
		{Algorithm: HS256, Key: covHMACKey2},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	// Verify with the second key: the loop skips signature 0 (verify fails ->
	// continue) and succeeds on signature 1, exercising the continue + success.
	idx, _, payload, err := obj.VerifyMulti(covHMACKey2)
	if err != nil {
		t.Fatalf("VerifyMulti: %v", err)
	}
	if idx != 1 {
		t.Errorf("VerifyMulti index = %d, want 1", idx)
	}
	if string(payload) != "payload" {
		t.Errorf("VerifyMulti payload = %q", payload)
	}

	// Unsupported key type -> newVerifier error path in DetachedVerifyMulti
	if _, _, _, err := obj.VerifyMulti("not-a-key"); err == nil {
		t.Error("VerifyMulti with bad key type: expected error")
	}

	// A wrong key for every signature -> all continue, then error.
	if _, _, _, err := obj.VerifyMulti([]byte("totally-wrong-key-of-right-length__")); err == nil {
		t.Error("VerifyMulti with wrong key: expected error")
	}
}

func TestSignWithNonceAndBadB64(t *testing.T) {
	// NonceSource branch in Sign.
	signer, err := NewSigner(
		SigningKey{Algorithm: HS256, Key: covHMACKey1},
		&SignerOptions{NonceSource: staticNonceSource("nonce-1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{HS256})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signatures[0].Protected.Nonce != "nonce-1" {
		t.Errorf("nonce = %q, want nonce-1", parsed.Signatures[0].Protected.Nonce)
	}

	// A non-bool "b64" protected header -> "Invalid b64 header parameter".
	badB64 := &SignerOptions{}
	badB64.WithHeader("b64", "not-a-bool")
	signer2, err := NewSigner(SigningKey{Algorithm: HS256, Key: covHMACKey1}, badB64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer2.Sign([]byte("payload")); err == nil {
		t.Error("Sign with non-bool b64 header: expected error")
	}
}
