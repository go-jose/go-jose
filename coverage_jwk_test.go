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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
	"testing"
)

// thumbprintOpaqueSigner is a minimal OpaqueSigner whose Public() returns a JWK
// wrapping a concrete public key, so Thumbprint's OpaqueSigner branch resolves.
type thumbprintOpaqueSigner struct{}

func (thumbprintOpaqueSigner) Public() *JSONWebKey {
	return &JSONWebKey{Key: &rsaTestKey.PublicKey}
}
func (thumbprintOpaqueSigner) Algs() []SignatureAlgorithm { return []SignatureAlgorithm{RS256} }
func (thumbprintOpaqueSigner) SignPayload([]byte, SignatureAlgorithm) ([]byte, error) {
	return nil, nil
}

func TestThumbprintAllKeyTypes(t *testing.T) {
	keys := map[string]interface{}{
		"ed25519 public":  ed25519PublicKey,
		"ed25519 private": ed25519PrivateKey,
		"ecdsa public":    &ecTestKey256.PublicKey,
		"ecdsa private":   ecTestKey256,
		"rsa public":      &rsaTestKey.PublicKey,
		"rsa private":     rsaTestKey,
		"opaque signer":   thumbprintOpaqueSigner{},
	}
	for name, key := range keys {
		jwk := &JSONWebKey{Key: key}
		if _, err := jwk.Thumbprint(crypto.SHA256); err != nil {
			t.Errorf("Thumbprint(%s): %v", name, err)
		}
	}

	// Unknown key type -> default error branch
	if _, err := (&JSONWebKey{Key: "not-a-key"}).Thumbprint(crypto.SHA256); err == nil {
		t.Error("Thumbprint of unknown key type: expected error")
	}
}

func TestThumbprintInputErrorBranches(t *testing.T) {
	// ecThumbprintInput: coordinate larger than the curve size
	tooBig := new(big.Int).Lsh(big.NewInt(1), 8*40) // 41 bytes, > P-256's 32
	if _, err := ecThumbprintInput(elliptic.P256(), tooBig, big.NewInt(1)); err == nil {
		t.Error("ecThumbprintInput with oversized x: expected error")
	}
	// edThumbprintInput: key longer than 32 bytes
	if _, err := edThumbprintInput(make(ed25519.PublicKey, 33)); err == nil {
		t.Error("edThumbprintInput with oversized key: expected error")
	}
}

func TestJSONWebKeyValid(t *testing.T) {
	cases := []struct {
		name string
		key  interface{}
		want bool
	}{
		{"nil", nil, false},
		{"ecdsa public valid", &ecTestKey256.PublicKey, true},
		{"ecdsa public nil curve", &ecdsa.PublicKey{}, false},
		{"ecdsa private valid", ecTestKey256, true},
		{"ecdsa private incomplete", &ecdsa.PrivateKey{}, false},
		{"rsa public valid", &rsaTestKey.PublicKey, true},
		{"rsa public zero e", &rsa.PublicKey{N: big.NewInt(1)}, false},
		{"rsa private valid", rsaTestKey, true},
		{"rsa private incomplete", &rsa.PrivateKey{}, false},
		{"ed public valid", ed25519PublicKey, true},
		{"ed public wrong len", ed25519.PublicKey(make([]byte, 5)), false},
		{"ed private valid", ed25519PrivateKey, true},
		{"ed private wrong len", ed25519.PrivateKey(make([]byte, 5)), false},
		{"unknown", "not-a-key", false},
	}
	for _, c := range cases {
		if got := (&JSONWebKey{Key: c.key}).Valid(); got != c.want {
			t.Errorf("Valid(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestJSONWebKeyUnmarshalErrorBranches(t *testing.T) {
	bad := []string{
		`{"kty":"oct","k":"AA","x5c":["!"]}`,       // x5c parse error
		`{"kty":"OKP","crv":"Ed25519","d":"AA"}`,   // ed private missing X
		`{"kty":"OKP","crv":"Ed25519"}`,            // ed public missing X
		`{"kty":"oct","k":"AA","x5t":"!"}`,         // x5t invalid base64
		`{"kty":"oct","k":"AA","x5t#S256":"!"}`,    // x5t#S256 invalid base64
		`{"kty":"oct","k":"AA","x5t":"AAAA"}`,      // x5t wrong size
		`{"kty":"oct","k":"AA","x5t#S256":"AAAA"}`, // x5t#S256 wrong size
		`{"kty":"EC","crv":"P-256","d":"AA"}`,      // ec private missing coords
	}
	for _, s := range bad {
		var k JSONWebKey
		if err := k.UnmarshalJSON([]byte(s)); err == nil {
			t.Errorf("UnmarshalJSON(%s): expected error", s)
		}
	}
}

func TestJSONWebKeyMarshalThumbprintErrors(t *testing.T) {
	if _, err := (&JSONWebKey{
		Key:                       &rsaTestKey.PublicKey,
		CertificateThumbprintSHA1: []byte("too-short"),
	}).MarshalJSON(); err == nil {
		t.Error("MarshalJSON with bad SHA-1 thumbprint: expected error")
	}
	if _, err := (&JSONWebKey{
		Key:                         &rsaTestKey.PublicKey,
		CertificateThumbprintSHA256: []byte("too-short"),
	}).MarshalJSON(); err == nil {
		t.Error("MarshalJSON with bad SHA-256 thumbprint: expected error")
	}
}

func TestTryJWKSBranches(t *testing.T) {
	// Non-JWKS key is returned unchanged.
	if got, err := tryJWKS(covHMACKey1, Header{}); err != nil || got == nil {
		t.Errorf("tryJWKS non-JWKS = (%v,%v)", got, err)
	}
	// JWKS by value, no kid in header -> rejected.
	if _, err := tryJWKS(JSONWebKeySet{}, Header{}); err == nil {
		t.Error("tryJWKS with no kid: expected error")
	}
	// JWKS by pointer, kid not present -> rejected.
	set := &JSONWebKeySet{Keys: []JSONWebKey{{KeyID: "a", Key: &rsaTestKey.PublicKey}}}
	if _, err := tryJWKS(set, Header{KeyID: "missing"}); err == nil {
		t.Error("tryJWKS with unknown kid: expected error")
	}
	// JWKS by pointer, matching kid -> returns the key.
	if got, err := tryJWKS(set, Header{KeyID: "a"}); err != nil || got == nil {
		t.Errorf("tryJWKS matching kid = (%v,%v)", got, err)
	}
}

func TestJSONWebKeyPublic(t *testing.T) {
	// Private keys -> their public halves.
	for name, key := range map[string]interface{}{
		"ecdsa":   ecTestKey256,
		"rsa":     rsaTestKey,
		"ed25519": ed25519PrivateKey,
	} {
		pub := (&JSONWebKey{Key: key}).Public()
		if !pub.IsPublic() {
			t.Errorf("Public(%s) did not return a public key", name)
		}
	}

	// Already-public key -> returned unchanged.
	pubIn := &JSONWebKey{Key: &rsaTestKey.PublicKey}
	pubOut := pubIn.Public()
	if !pubOut.IsPublic() {
		t.Error("Public() of a public key should stay public")
	}

	// Non-asymmetric key -> empty (invalid) key from the default branch.
	empty := (&JSONWebKey{Key: []byte("symmetric")}).Public()
	if empty.Key != nil {
		t.Errorf("Public() of symmetric key = %v, want empty", empty.Key)
	}
}
