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

func TestJWSParseErrorBranches(t *testing.T) {
	algs := []SignatureAlgorithm{HS256}

	// Empty signature-algorithm list.
	if _, err := ParseSignedJSON(`{"payload":"dGVzdA","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"AAAA"}`, nil); err == nil {
		t.Error("ParseSignedJSON with no algorithms: expected error")
	}

	jsonCases := map[string]string{
		// flattened: protected header field of wrong type (kid as number)
		"flattened bad kid": `{"payload":"dGVzdA","protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6NX0","signature":"AAAA"}`,
		// signatures array: protected decodes to "{" which is invalid header JSON
		"array bad protected json": `{"payload":"dGVzdA","signatures":[{"protected":"ew","signature":"AAAA"}]}`,
		// signatures array: embedded jwk is a non-public (symmetric) key
		"array non-public jwk": `{"payload":"dGVzdA","signatures":[{"protected":"eyJhbGciOiJIUzI1NiIsImp3ayI6eyJrdHkiOiJvY3QiLCJrIjoiQUEifX0","signature":"AAAA"}]}`,
	}
	for name, s := range jsonCases {
		if _, err := ParseSignedJSON(s, algs); err == nil {
			t.Errorf("ParseSignedJSON(%s): expected error", name)
		}
	}

	// ParseSignedCompact wrapper: malformed compact token.
	if _, err := ParseSignedCompact("only.two", algs); err == nil {
		t.Error("ParseSignedCompact with too few parts: expected error")
	}
	// ParseSignedCompact: protected segment is not valid base64url.
	if _, err := ParseSignedCompact("!.AAAA.AAAA", algs); err == nil {
		t.Error("ParseSignedCompact with bad base64: expected error")
	}
}

func TestCheckSupportedCriticalError(t *testing.T) {
	// getCritical returns an error (crit is not an array), propagated out.
	h := rawHeader{headerCritical: rawMsg(`5`)}
	if err := h.checkSupportedCritical(supportedCritical); err == nil {
		t.Error("checkSupportedCritical with malformed crit: expected error")
	}
}

func TestVerifyWithJWKKey(t *testing.T) {
	// newVerifier's JSONWebKey and *JSONWebKey recursion branches.
	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: covHMACKey1}, nil)
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
	if _, err := parsed.Verify(JSONWebKey{Key: covHMACKey1}); err != nil {
		t.Errorf("Verify with JSONWebKey value: %v", err)
	}
	if _, err := parsed.Verify(&JSONWebKey{Key: covHMACKey1}); err != nil {
		t.Errorf("Verify with *JSONWebKey: %v", err)
	}
}
