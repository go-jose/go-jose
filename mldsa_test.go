//go:build go1.27

/*-
 * Copyright 2014 Square Inc.
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
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/json"
)

func TestMLDSAAlgParamsRoundtrip(t *testing.T) {
	for _, alg := range mldsaAlgs {
		params, ok := mldsaParamsFor(alg)
		if !ok {
			t.Fatalf("mldsaParamsFor(%s) = _, false; want true", alg)
		}
		got, ok := mldsaAlgFor(params)
		if !ok || got != alg {
			t.Errorf("mldsaAlgFor(%v) = %q, %v; want %q, true", params, got, ok, alg)
		}
	}
}

func TestMLDSAAlgParamsRejectsUnknown(t *testing.T) {
	if _, ok := mldsaParamsFor(EdDSA); ok {
		t.Error("mldsaParamsFor(EdDSA) = _, true; want false")
	}
	if _, ok := mldsaParamsFor(SignatureAlgorithm("ML-DSA-99")); ok {
		t.Error(`mldsaParamsFor("ML-DSA-99") = _, true; want false`)
	}
	if _, ok := mldsaAlgFor(mldsa.Parameters{}); ok {
		t.Error("mldsaAlgFor(zero Parameters) = _, true; want false")
	}
}

func TestMLDSAKeyPredicates(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		privJWK := &JSONWebKey{Key: priv}
		pubJWK := &JSONWebKey{Key: priv.PublicKey()}

		if privJWK.IsPublic() {
			t.Errorf("%s: private key JWK reported as public", alg)
		}
		if !pubJWK.IsPublic() {
			t.Errorf("%s: public key JWK not reported as public", alg)
		}
		if !privJWK.Valid() {
			t.Errorf("%s: private key JWK reported invalid", alg)
		}
		if !pubJWK.Valid() {
			t.Errorf("%s: public key JWK reported invalid", alg)
		}

		derived := privJWK.Public()
		if !derived.IsPublic() {
			t.Fatalf("%s: Public() did not return a public key", alg)
		}
		got, ok := derived.Key.(*mldsa.PublicKey)
		if !ok {
			t.Fatalf("%s: Public() returned %T; want *mldsa.PublicKey", alg, derived.Key)
		}
		if !got.Equal(priv.PublicKey()) {
			t.Errorf("%s: Public() returned the wrong public key", alg)
		}

		// Public() on an already-public key is the identity.
		if again := pubJWK.Public(); !again.IsPublic() {
			t.Errorf("%s: Public() on a public key did not round-trip", alg)
		}
	}
}

func TestMLDSANilKeysAreInvalid(t *testing.T) {
	var (
		nilPriv *mldsa.PrivateKey
		nilPub  *mldsa.PublicKey
	)
	if (&JSONWebKey{Key: nilPriv}).Valid() {
		t.Error("nil *mldsa.PrivateKey reported valid")
	}
	if (&JSONWebKey{Key: nilPub}).Valid() {
		t.Error("nil *mldsa.PublicKey reported valid")
	}
}

func TestMLDSAUnusableKeysDoNotPanic(t *testing.T) {
	var nilPriv *mldsa.PrivateKey
	var nilPub *mldsa.PublicKey
	zeroPriv := new(mldsa.PrivateKey)
	zeroPub := new(mldsa.PublicKey)

	t.Run("private", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			key  *mldsa.PrivateKey
		}{
			{"typed-nil", nilPriv},
			{"zero-value", zeroPriv},
		} {
			t.Run(tc.name, func(t *testing.T) {
				jwk := &JSONWebKey{Key: tc.key}

				if jwk.Valid() {
					t.Error("Valid() = true; want false")
				}
				if jwk.IsPublic() {
					t.Error("IsPublic() = true; want false")
				}
				if _, err := NewSigner(SigningKey{Algorithm: ML_DSA_65, Key: tc.key}, nil); err == nil {
					t.Error("NewSigner accepted the key")
				}
				if _, err := jwk.MarshalJSON(); err == nil {
					t.Error("MarshalJSON accepted the key")
				}
				if _, err := jwk.Thumbprint(crypto.SHA256); err == nil {
					t.Error("Thumbprint accepted the key")
				}
			})
		}
	})

	realPriv := mldsaTestKey(t, ML_DSA_65)
	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_65, Key: realPriv}, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("public", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			key  *mldsa.PublicKey
		}{
			{"typed-nil", nilPub},
			{"zero-value", zeroPub},
		} {
			t.Run(tc.name, func(t *testing.T) {
				jwk := &JSONWebKey{Key: tc.key}

				if jwk.Valid() {
					t.Error("Valid() = true; want false")
				}
				if jwk.IsPublic() {
					t.Error("IsPublic() = true; want false")
				}
				if _, err := obj.Verify(tc.key); err == nil {
					t.Error("Verify accepted the key")
				}
				if _, err := jwk.MarshalJSON(); err == nil {
					t.Error("MarshalJSON accepted the key")
				}
				if _, err := jwk.Thumbprint(crypto.SHA256); err == nil {
					t.Error("Thumbprint accepted the key")
				}
			})
		}
	})
}

func TestMLDSARoundtripJWS(t *testing.T) {
	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}
	corrupter := func(obj *JSONWebSignature) {}

	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		for i, serializer := range serializers {
			t.Run(fmt.Sprintf("%s-serializer%d", alg, i), func(t *testing.T) {
				if err := RoundtripJWS(alg, serializer, corrupter, priv, priv.PublicKey(), "test_nonce"); err != nil {
					t.Error(err)
				}
			})
		}
	}
}

func TestMLDSARoundtripJWSCorruptSignature(t *testing.T) {
	corrupter := func(obj *JSONWebSignature) {
		obj.Signatures[0].Signature[10]++
	}
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		err := RoundtripJWS(alg, func(obj *JSONWebSignature) (string, error) {
			return obj.CompactSerialize()
		}, corrupter, priv, priv.PublicKey(), "")
		if err == nil {
			t.Errorf("%s: corrupt signature verified successfully", alg)
		}
	}
}

func TestMLDSASignerRejectsMismatchedAlg(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	for _, alg := range []SignatureAlgorithm{ML_DSA_65, ML_DSA_87, EdDSA, ES256} {
		if _, err := NewSigner(SigningKey{Algorithm: alg, Key: priv}, nil); err == nil {
			t.Errorf("NewSigner accepted an ML-DSA-44 key for %s", alg)
		}
	}
}

func TestMLDSAVerifierRejectsMismatchedAlg(t *testing.T) {
	priv44 := mldsaTestKey(t, ML_DSA_44)
	priv65 := mldsaTestKey(t, ML_DSA_65)

	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_44, Key: priv44}, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	msg, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	parsed, err := ParseSigned(msg, []SignatureAlgorithm{ML_DSA_44, ML_DSA_65})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	if _, err := parsed.Verify(priv65.PublicKey()); err == nil {
		t.Error("an ML-DSA-65 key verified an ML-DSA-44 signature")
	}
}

func TestMLDSAVerifyPayloadRejectsMismatchedAlg(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_65)
	payload := []byte("Lorem ipsum dolor sit amet")

	sig, err := priv.Sign(randReader, payload, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifier, ok, err := mldsaVerifier(priv.PublicKey())
	if !ok || err != nil {
		t.Fatalf("mldsaVerifier(pub) = _, %v, %v; want _, true, nil", ok, err)
	}

	if err := verifier.verifyPayload(payload, sig, ML_DSA_65); err != nil {
		t.Fatalf("verifyPayload(ML_DSA_65) failed on a matching key/signature pair: %v", err)
	}

	if err := verifier.verifyPayload(payload, sig, ML_DSA_44); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("verifyPayload(ML_DSA_44) = %v; want ErrUnsupportedAlgorithm", err)
	}
}

func TestMLDSASignPayloadRejectsMismatchedAlg(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_65)
	payload := []byte("Lorem ipsum dolor sit amet")

	signer := &mldsaPrivateKeySigner{privateKey: priv, alg: ML_DSA_65}

	if _, err := signer.signPayload(payload, ML_DSA_65); err != nil {
		t.Fatalf("signPayload(ML_DSA_65) failed on a matching signer: %v", err)
	}

	if _, err := signer.signPayload(payload, ML_DSA_44); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("signPayload(ML_DSA_44) = _, %v; want ErrUnsupportedAlgorithm", err)
	}
}

func TestMLDSASignWithJSONWebKey(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		signingKey := JSONWebKey{Key: priv, KeyID: "test-kid", Algorithm: string(alg)}

		signer, err := NewSigner(SigningKey{Algorithm: alg, Key: signingKey}, nil)
		if err != nil {
			t.Fatalf("%s: NewSigner with JSONWebKey: %v", alg, err)
		}
		obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}
		serialized, err := obj.CompactSerialize()
		if err != nil {
			t.Fatalf("%s: CompactSerialize: %v", alg, err)
		}
		parsed, err := ParseSigned(serialized, []SignatureAlgorithm{alg})
		if err != nil {
			t.Fatalf("%s: ParseSigned: %v", alg, err)
		}
		if kid := parsed.Signatures[0].Header.KeyID; kid != "test-kid" {
			t.Errorf("%s: KeyID = %q; want %q", alg, kid, "test-kid")
		}
		if _, err := parsed.Verify(&JSONWebKey{Key: priv.PublicKey()}); err != nil {
			t.Errorf("%s: Verify with JSONWebKey: %v", alg, err)
		}
	}
}

func TestMLDSASignaturesAreRandomized(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_44, Key: priv}, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	payload := []byte("Lorem ipsum dolor sit amet")
	first, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	second, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if bytes.Equal(first.Signatures[0].Signature, second.Signatures[0].Signature) {
		t.Error("two signatures over the same payload were identical; expected randomized signing")
	}
}

func TestMLDSAMarshalPublicJWK(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)

		data, err := (&JSONWebKey{Key: priv.PublicKey()}).MarshalJSON()
		if err != nil {
			t.Fatalf("%s: MarshalJSON: %v", alg, err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("%s: unmarshal into map: %v", alg, err)
		}
		if raw["kty"] != "AKP" {
			t.Errorf("%s: kty = %v; want AKP", alg, raw["kty"])
		}

		// RFC 9964 makes alg REQUIRED, and it is derived from the key itself.
		if raw["alg"] != string(alg) {
			t.Errorf("%s: alg = %v; want %s", alg, raw["alg"], alg)
		}
		if _, ok := raw["priv"]; ok {
			t.Errorf("%s: public JWK contains priv", alg)
		}
		pub, err := base64.RawURLEncoding.DecodeString(raw["pub"].(string))
		if err != nil {
			t.Fatalf("%s: pub is not raw base64url: %v", alg, err)
		}
		if len(pub) != mldsaExpectedPubSize[alg] {
			t.Errorf("%s: len(pub) = %d; want %d", alg, len(pub), mldsaExpectedPubSize[alg])
		}

		// Nothing from the EC/RSA/OKP vocabulary belongs on an AKP key.
		for _, member := range []string{"crv", "x", "y", "d", "n", "e", "k"} {
			if _, ok := raw[member]; ok {
				t.Errorf("%s: AKP JWK unexpectedly contains %q", alg, member)
			}
		}
	}
}

func TestMLDSAMarshalPrivateJWK(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)

		data, err := (&JSONWebKey{Key: priv}).MarshalJSON()
		if err != nil {
			t.Fatalf("%s: MarshalJSON: %v", alg, err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("%s: unmarshal into map: %v", alg, err)
		}
		if raw["kty"] != "AKP" || raw["alg"] != string(alg) {
			t.Errorf("%s: kty/alg = %v/%v; want AKP/%s", alg, raw["kty"], raw["alg"], alg)
		}

		// RFC 9964: priv MUST be the seed and MUST be 32 bytes.
		seed, err := base64.RawURLEncoding.DecodeString(raw["priv"].(string))
		if err != nil {
			t.Fatalf("%s: priv is not raw base64url: %v", alg, err)
		}
		if len(seed) != mldsa.PrivateKeySize {
			t.Errorf("%s: len(priv) = %d; want %d", alg, len(seed), mldsa.PrivateKeySize)
		}
		if !bytes.Equal(seed, priv.Bytes()) {
			t.Errorf("%s: priv is not the key's seed", alg)
		}

		// A private AKP JWK carries the public half too.
		pub, err := base64.RawURLEncoding.DecodeString(raw["pub"].(string))
		if err != nil {
			t.Fatalf("%s: pub is not raw base64url: %v", alg, err)
		}
		if !bytes.Equal(pub, priv.PublicKey().Bytes()) {
			t.Errorf("%s: pub does not match the key's public half", alg)
		}
	}
}

func TestMLDSAMarshalRejectsContradictoryAlgorithm(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)

	if _, err := (&JSONWebKey{Key: priv, Algorithm: string(ML_DSA_44)}).MarshalJSON(); err != nil {
		t.Errorf("MarshalJSON with matching Algorithm: %v", err)
	}

	if _, err := (&JSONWebKey{Key: priv}).MarshalJSON(); err != nil {
		t.Errorf("MarshalJSON with empty Algorithm: %v", err)
	}

	if _, err := (&JSONWebKey{Key: priv, Algorithm: string(ML_DSA_87)}).MarshalJSON(); err == nil {
		t.Error("MarshalJSON accepted an Algorithm contradicting the key's parameter set")
	}

	if _, err := (&JSONWebKey{Key: priv, Algorithm: "EdDSA"}).MarshalJSON(); err == nil {
		t.Error("MarshalJSON accepted Algorithm=EdDSA on an ML-DSA key")
	}
}

func TestMLDSAEmbedJWKWithContradictoryAlgorithm(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	signingKey := JSONWebKey{Key: priv, Algorithm: string(ML_DSA_87)}

	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_44, Key: signingKey}, &SignerOptions{EmbedJWK: true})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := signer.Sign([]byte("Lorem ipsum dolor sit amet")); err == nil {
		t.Error("Sign accepted a signing key whose embedded JWK Algorithm contradicts its parameter set")
	}
}

func TestMLDSAMarshalPreservesOtherKtyAlgHandling(t *testing.T) {
	data, err := (&JSONWebKey{Key: ed25519PublicKey, Algorithm: "EdDSA"}).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if raw["alg"] != "EdDSA" {
		t.Errorf("alg = %v; want EdDSA", raw["alg"])
	}
}

func TestMLDSAJWKRoundtrip(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)

		for _, tc := range []struct {
			name string
			key  interface{}
		}{
			{"public", priv.PublicKey()},
			{"private", priv},
		} {
			t.Run(fmt.Sprintf("%s-%s", alg, tc.name), func(t *testing.T) {
				data, err := (&JSONWebKey{Key: tc.key, KeyID: "kid-1", Use: "sig"}).MarshalJSON()
				if err != nil {
					t.Fatalf("MarshalJSON: %v", err)
				}

				var parsed JSONWebKey
				if err := parsed.UnmarshalJSON(data); err != nil {
					t.Fatalf("UnmarshalJSON: %v", err)
				}
				if parsed.KeyID != "kid-1" || parsed.Use != "sig" || parsed.Algorithm != string(alg) {
					t.Errorf("metadata lost: kid=%q use=%q alg=%q", parsed.KeyID, parsed.Use, parsed.Algorithm)
				}

				switch want := tc.key.(type) {
				case *mldsa.PublicKey:
					got, ok := parsed.Key.(*mldsa.PublicKey)
					if !ok {
						t.Fatalf("parsed key is %T; want *mldsa.PublicKey", parsed.Key)
					}
					if !got.Equal(want) {
						t.Error("parsed public key differs from the original")
					}
				case *mldsa.PrivateKey:
					got, ok := parsed.Key.(*mldsa.PrivateKey)
					if !ok {
						t.Fatalf("parsed key is %T; want *mldsa.PrivateKey", parsed.Key)
					}
					if !got.Equal(want) {
						t.Error("parsed private key differs from the original")
					}
				}
			})
		}
	}
}

// TestMLDSAParsedJWKSigns proves a parsed key is usable, not merely equal.
func TestMLDSAParsedJWKSigns(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_65)
	data, err := (&JSONWebKey{Key: priv}).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var parsed JSONWebKey
	if err := parsed.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if err := RoundtripJWS(ML_DSA_65, func(obj *JSONWebSignature) (string, error) {
		return obj.CompactSerialize()
	}, func(*JSONWebSignature) {}, parsed.Key, priv.PublicKey(), ""); err != nil {
		t.Error(err)
	}
}

func TestMLDSAParseJWKRejects(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	pub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	pub65 := base64.RawURLEncoding.EncodeToString(mldsaTestKey(t, ML_DSA_65).PublicKey().Bytes())
	otherSeed := base64.RawURLEncoding.EncodeToString(mldsaTestKey(t, ML_DSA_44).Bytes())

	for _, tc := range []struct {
		name string
		json string
	}{
		{
			"missing alg",
			fmt.Sprintf(`{"kty":"AKP","pub":%q}`, pub),
		},
		{
			"unrecognized alg",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-99","pub":%q}`, pub),
		},
		{
			"non ML-DSA alg",
			fmt.Sprintf(`{"kty":"AKP","alg":"EdDSA","pub":%q}`, pub),
		},
		{
			"neither pub nor priv",
			`{"kty":"AKP","alg":"ML-DSA-44"}`,
		},
		{
			"pub length disagrees with alg",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q}`, pub65),
		},
		{
			"priv is not 32 bytes",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","priv":%q}`, pub),
		},
		{
			"pub disagrees with priv",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"priv":%q}`, pub, otherSeed),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var key JSONWebKey
			if err := key.UnmarshalJSON([]byte(tc.json)); err == nil {
				t.Errorf("UnmarshalJSON accepted %s", tc.name)
			}
		})
	}
}

func TestMLDSAJWKWithCertificateChain(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	other := mldsaTestKey(t, ML_DSA_44)

	newCert := func(key *mldsa.PrivateKey) string {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "ml-dsa test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			SignatureAlgorithm:    x509.MLDSA44,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		return base64.StdEncoding.EncodeToString(der)
	}

	pub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	// Matching chain: accepted.
	matching := fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"x5c":[%q]}`, pub, newCert(priv))
	var key JSONWebKey
	if err := key.UnmarshalJSON([]byte(matching)); err != nil {
		t.Errorf("UnmarshalJSON with a matching x5c: %v", err)
	}

	// Mismatched chain: rejected.
	mismatched := fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"x5c":[%q]}`, pub, newCert(other))
	var bad JSONWebKey
	if err := bad.UnmarshalJSON([]byte(mismatched)); err == nil {
		t.Error("UnmarshalJSON accepted a JWK whose x5c leaf does not match pub")
	}
}

func TestMLDSAThumbprint(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)

		want := sha256.Sum256([]byte(fmt.Sprintf(
			`{"alg":"%s","kty":"AKP","pub":"%s"}`,
			alg,
			base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		)))

		got, err := (&JSONWebKey{Key: priv.PublicKey()}).Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("%s: Thumbprint: %v", alg, err)
		}
		if !bytes.Equal(got, want[:]) {
			t.Errorf("%s: thumbprint = %x; want %x", alg, got, want[:])
		}

		fromPriv, err := (&JSONWebKey{Key: priv}).Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("%s: Thumbprint of private key: %v", alg, err)
		}
		if !bytes.Equal(fromPriv, got) {
			t.Errorf("%s: private and public thumbprints differ", alg)
		}
	}
}

func TestMLDSAThumbprintDiffersByAlg(t *testing.T) {
	seen := map[string]SignatureAlgorithm{}
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		tp, err := (&JSONWebKey{Key: priv.PublicKey()}).Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("%s: Thumbprint: %v", alg, err)
		}
		if prev, ok := seen[string(tp)]; ok {
			t.Errorf("%s collided with %s", alg, prev)
		}
		seen[string(tp)] = alg

		withoutAlg := sha256.Sum256([]byte(fmt.Sprintf(
			`{"kty":"AKP","pub":"%s"}`,
			base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		)))
		if bytes.Equal(tp, withoutAlg[:]) {
			t.Errorf("%s: thumbprint is unaffected by omitting alg from the template", alg)
		}
	}
}

var mldsaExpectedPubSize = map[SignatureAlgorithm]int{
	ML_DSA_44: mldsa.MLDSA44PublicKeySize,
	ML_DSA_65: mldsa.MLDSA65PublicKeySize,
	ML_DSA_87: mldsa.MLDSA87PublicKeySize,
}

var mldsaAlgs = []SignatureAlgorithm{ML_DSA_44, ML_DSA_65, ML_DSA_87}

func mldsaTestKey(t *testing.T, alg SignatureAlgorithm) *mldsa.PrivateKey {
	t.Helper()
	params, ok := mldsaParamsFor(alg)
	if !ok {
		t.Fatalf("mldsaParamsFor(%s): unknown algorithm", alg)
	}
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatalf("mldsa.GenerateKey(%s): %v", alg, err)
	}
	return key
}
