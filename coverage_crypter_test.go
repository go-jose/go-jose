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

// A two-recipient JWE in JSON serialization.
const covMultiRecipientJWE = `{"protected":"eyJlbmMiOiJBMTI4R0NNIn0",` +
	`"recipients":[{"header":{"alg":"A128KW"},"encrypted_key":"AAAA"},` +
	`{"header":{"alg":"A256KW"},"encrypted_key":"BBBB"}],` +
	`"iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"}`

// A single-recipient JWE whose protected header carries a "crit" parameter.
const covCritJWE = `{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIiwiY3JpdCI6WyJ4Il19",` +
	`"iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"}`

// A single-recipient JWE naming a content encryption with no cipher.
const covBogusEncJWE = `{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJCT0dVUyJ9",` +
	`"iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"}`

// A well-formed single-recipient dir/A128GCM JWE (decryption fails on the tag).
const covDirJWE = `{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0",` +
	`"iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"}`

func parseJWE(t *testing.T, s string, enc ...ContentEncryption) *JSONWebEncryption {
	t.Helper()
	if len(enc) == 0 {
		enc = []ContentEncryption{A128GCM}
	}
	obj, err := ParseEncryptedJSON(s, []KeyAlgorithm{DIRECT, A128KW, A256KW}, enc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return obj
}

func TestDecryptErrorBranches(t *testing.T) {
	key := make([]byte, 16)

	// More than one recipient.
	if _, err := parseJWE(t, covMultiRecipientJWE).Decrypt(key); err == nil {
		t.Error("Decrypt with multiple recipients: expected error")
	}
	// "crit" present -> checkNoCritical.
	if _, err := parseJWE(t, covCritJWE).Decrypt(key); err == nil {
		t.Error("Decrypt with crit header: expected error")
	}
	// Unsupported key type -> newDecrypter error.
	if _, err := parseJWE(t, covDirJWE).Decrypt("not-a-key"); err == nil {
		t.Error("Decrypt with bad key type: expected error")
	}
	// Unsupported content encryption -> nil cipher.
	if _, err := parseJWE(t, covBogusEncJWE, "BOGUS").Decrypt(key); err == nil {
		t.Error("Decrypt with unsupported enc: expected error")
	}
	// Valid structure, wrong/short key material -> ErrCryptoFailure.
	if _, err := parseJWE(t, covDirJWE).Decrypt(key); err == nil {
		t.Error("Decrypt of corrupt ciphertext: expected error")
	}
}

func TestNewMultiEncrypterBranches(t *testing.T) {
	aesKey := make([]byte, 16)

	// Unsupported content encryption -> nil cipher.
	if _, err := NewMultiEncrypter("BOGUS", []Recipient{{Algorithm: A128KW, Key: aesKey}}, nil); err == nil {
		t.Error("NewMultiEncrypter with bad enc: expected error")
	}
	// No recipients.
	if _, err := NewMultiEncrypter(A128GCM, nil, nil); err == nil {
		t.Error("NewMultiEncrypter with no recipients: expected error")
	}
	// DIRECT is not allowed in multi-recipient mode -> addRecipient error.
	if _, err := NewMultiEncrypter(A128GCM, []Recipient{{Algorithm: DIRECT, Key: aesKey}}, nil); err == nil {
		t.Error("NewMultiEncrypter with DIRECT: expected error")
	}
	// Unsupported key type -> makeJWERecipient error.
	if _, err := NewMultiEncrypter(A128GCM, []Recipient{{Algorithm: A128KW, Key: 12345}}, nil); err == nil {
		t.Error("NewMultiEncrypter with bad key type: expected error")
	}

	// PBES2 recipient exercises the p2c/p2s assignment branch in addRecipient.
	enc, err := NewMultiEncrypter(A128GCM, []Recipient{{
		Algorithm:  PBES2_HS256_A128KW,
		Key:        []byte("password"),
		PBES2Count: 4096,
		PBES2Salt:  make([]byte, 16),
	}}, nil)
	if err != nil {
		t.Fatalf("NewMultiEncrypter PBES2: %v", err)
	}
	if _, err := enc.Encrypt([]byte("hi")); err != nil {
		t.Fatalf("Encrypt PBES2: %v", err)
	}
}

func TestEncryptDecryptWithJWKKey(t *testing.T) {
	// JSONWebKey (value and pointer) routing in makeJWERecipient and newDecrypter.
	aesKey := make([]byte, 16)
	jwk := JSONWebKey{Key: aesKey, KeyID: "k1"}

	enc, err := NewEncrypter(A128GCM, Recipient{Algorithm: A128KW, Key: jwk}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.Decrypt(&jwk)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "secret" {
		t.Errorf("decrypt = %q, want secret", out)
	}
}

func TestDecryptMultiErrorBranches(t *testing.T) {
	key := make([]byte, 16)

	// "crit" present -> checkNoCritical.
	if _, _, _, err := parseJWE(t, covCritJWE).DecryptMulti(key); err == nil {
		t.Error("DecryptMulti with crit header: expected error")
	}
	// Unsupported key type -> newDecrypter error.
	if _, _, _, err := parseJWE(t, covDirJWE).DecryptMulti("not-a-key"); err == nil {
		t.Error("DecryptMulti with bad key type: expected error")
	}
	// Unsupported content encryption -> nil cipher.
	if _, _, _, err := parseJWE(t, covBogusEncJWE, "BOGUS").DecryptMulti(key); err == nil {
		t.Error("DecryptMulti with unsupported enc: expected error")
	}
	// No recipient can decrypt -> error.
	if _, _, _, err := parseJWE(t, covMultiRecipientJWE).DecryptMulti(make([]byte, 16)); err == nil {
		t.Error("DecryptMulti with no working recipient: expected error")
	}
}
