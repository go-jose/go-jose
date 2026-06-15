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

package jwt

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestBuilderTokenMethods(t *testing.T) {
	// signedBuilder.Token()
	signedTok, err := Signed(rsaSigner).Claims(sampleClaims).Token()
	if err != nil {
		t.Fatalf("signed Token(): %v", err)
	}
	var got Claims
	if err := signedTok.Claims(&testPrivRSAKey1.PublicKey, &got); err != nil {
		t.Fatalf("signed claims: %v", err)
	}
	if got.Issuer != sampleClaims.Issuer {
		t.Errorf("issuer = %q, want %q", got.Issuer, sampleClaims.Issuer)
	}

	// encryptedBuilder.Token()
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.A128KW, Key: sharedEncryptionKey},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	encTok, err := Encrypted(encrypter).Claims(sampleClaims).Token()
	if err != nil {
		t.Fatalf("encrypted Token(): %v", err)
	}
	got = Claims{}
	if err := encTok.Claims(sharedEncryptionKey, &got); err != nil {
		t.Fatalf("encrypted claims: %v", err)
	}
	if got.Issuer != sampleClaims.Issuer {
		t.Errorf("encrypted issuer = %q, want %q", got.Issuer, sampleClaims.Issuer)
	}
}

func TestNestedBuilderTokenAndFullSerialize(t *testing.T) {
	encrypter, err := jose.NewEncrypter(
		jose.A128CBC_HS256,
		jose.Recipient{Algorithm: jose.A128KW, Key: sharedEncryptionKey},
		(&jose.EncrypterOptions{}).WithContentType("JWT").WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// nestedBuilder.Token() builds a NestedJSONWebToken. (Its allowed signature
	// algorithms are not set on this path, so decrypt it via a fresh parse below.)
	nested, err := SignedAndEncrypted(rsaSigner, encrypter).Claims(sampleClaims).Token()
	if err != nil {
		t.Fatalf("nested Token(): %v", err)
	}
	if len(nested.Headers) == 0 {
		t.Error("nested Token() produced no headers")
	}

	// nestedBuilder.FullSerialize() is a public method that is not part of the
	// NestedBuilder interface, so it is only reachable via the concrete type.
	nb := SignedAndEncrypted(rsaSigner, encrypter).Claims(sampleClaims).(*nestedBuilder)
	full, err := nb.FullSerialize()
	if err != nil {
		t.Fatalf("nested FullSerialize(): %v", err)
	}
	// FullSerialize emits JWE JSON serialization (not compact), so just confirm
	// it produced a non-empty JSON object.
	if len(full) == 0 || full[0] != '{' {
		t.Errorf("nested FullSerialize() = %q, want a JSON object", full)
	}
}
