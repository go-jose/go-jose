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

func TestJWEContainsAndValidateAlgEnc(t *testing.T) {
	// "not found" branches of the membership helpers.
	if containsKeyAlgorithm([]KeyAlgorithm{A128KW}, RSA1_5) {
		t.Error("containsKeyAlgorithm reported a missing algorithm as present")
	}
	if containsContentEncryption([]ContentEncryption{A128GCM}, A256GCM) {
		t.Error("containsContentEncryption reported a missing algorithm as present")
	}

	// validateAlgEnc: alg mismatch, enc mismatch, and the all-good path.
	good := rawHeader{headerAlgorithm: rawMsg(`"dir"`), headerEncryption: rawMsg(`"A128GCM"`)}
	if err := validateAlgEnc(good, []KeyAlgorithm{DIRECT}, []ContentEncryption{A128GCM}); err != nil {
		t.Errorf("validateAlgEnc valid = %v", err)
	}
	if err := validateAlgEnc(good, []KeyAlgorithm{A128KW}, []ContentEncryption{A128GCM}); err == nil {
		t.Error("validateAlgEnc with disallowed alg: expected error")
	}
	if err := validateAlgEnc(good, []KeyAlgorithm{DIRECT}, []ContentEncryption{A256GCM}); err == nil {
		t.Error("validateAlgEnc with disallowed enc: expected error")
	}
}

func TestParseEncryptedEmptyAlgLists(t *testing.T) {
	if _, err := ParseEncryptedJSON(covDirJWE, nil, []ContentEncryption{A128GCM}); err == nil {
		t.Error("ParseEncryptedJSON with no key algorithms: expected error")
	}
	if _, err := ParseEncryptedJSON(covDirJWE, []KeyAlgorithm{DIRECT}, nil); err == nil {
		t.Error("ParseEncryptedJSON with no content encryption: expected error")
	}
}

func TestRawJWKKeyParseErrors(t *testing.T) {
	// Ed25519: missing D and/or X.
	if _, err := (rawJSONWebKey{}).edPrivateKey(); err == nil {
		t.Error("edPrivateKey with missing D/X: expected error")
	}
	if _, err := (rawJSONWebKey{D: newBuffer([]byte("d"))}).edPrivateKey(); err == nil {
		t.Error("edPrivateKey with missing X: expected error")
	}
	if _, err := (rawJSONWebKey{}).edPublicKey(); err == nil {
		t.Error("edPublicKey with missing X: expected error")
	}

	// RSA private: missing fields.
	if _, err := (rawJSONWebKey{}).rsaPrivateKey(); err == nil {
		t.Error("rsaPrivateKey with missing fields: expected error")
	}

	// EC private: missing coordinates.
	if _, err := (rawJSONWebKey{Crv: "P-256"}).ecPrivateKey(); err == nil {
		t.Error("ecPrivateKey with missing X/Y/D: expected error")
	}
}

func TestParseDetachedBranches(t *testing.T) {
	// nil payload is rejected up front.
	if _, err := ParseDetached("a.b.c", nil, []SignatureAlgorithm{HS256}); err == nil {
		t.Error("ParseDetached with nil payload: expected error")
	}

	// Round-trip a detached signature so the success path is exercised.
	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: covHMACKey1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	detached, err := obj.DetachedCompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDetached(detached, []byte("payload"), []SignatureAlgorithm{HS256})
	if err != nil {
		t.Fatalf("ParseDetached: %v", err)
	}
	if err := parsed.DetachedVerify([]byte("payload"), covHMACKey1); err != nil {
		t.Errorf("DetachedVerify: %v", err)
	}
}
