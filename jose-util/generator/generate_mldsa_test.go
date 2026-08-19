//go:build go1.27

/*-
 * Copyright 2026 The Go JOSE Authors.
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

package generator

import (
	"crypto/mldsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestNewMLDSASigningKey(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.ML_DSA_44, jose.ML_DSA_65, jose.ML_DSA_87} {
		t.Run(string(alg), func(t *testing.T) {
			pub, priv, err := NewSigningKey(alg, 0)
			if err != nil {
				t.Fatalf("NewSigningKey: %v", err)
			}
			if _, ok := pub.(*mldsa.PublicKey); !ok {
				t.Errorf("public key is %T; want *mldsa.PublicKey", pub)
			}
			privKey, ok := priv.(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("private key is %T; want *mldsa.PrivateKey", priv)
			}

			// jose-util generate relies on all three of these.
			jwk := jose.JSONWebKey{Key: privKey, Algorithm: string(alg), Use: "sig"}
			if !jwk.Valid() {
				t.Error("generated private JWK is not valid")
			}
			if jwk.IsPublic() {
				t.Error("generated private JWK reported as public")
			}
			pubJWK := jwk.Public()
			if !pubJWK.IsPublic() {
				t.Error("Public() did not yield a public JWK")
			}
		})
	}
}

func TestNewSigningKeyStillRejectsUnknown(t *testing.T) {
	if _, _, err := NewSigningKey(jose.SignatureAlgorithm("bogus"), 0); err == nil {
		t.Error("NewSigningKey accepted an unknown algorithm")
	}
}
