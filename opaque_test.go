/*-
 * Copyright 2018 Square Inc.
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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
)

type signWrapper struct {
	pk      *JSONWebKey
	wrapped payloadSigner
	algs    []SignatureAlgorithm
}

var _ = OpaqueSigner(&signWrapper{})

func (sw *signWrapper) Algs() []SignatureAlgorithm {
	return sw.algs
}

func (sw *signWrapper) Public() *JSONWebKey {
	return sw.pk
}

func (sw *signWrapper) SignPayload(payload []byte, alg SignatureAlgorithm) ([]byte, error) {
	sig, err := sw.wrapped.signPayload(payload, alg)
	if err != nil {
		return nil, err
	}
	return sig.Signature, nil
}

type verifyWrapper struct {
	wrapped []payloadVerifier
}

var _ = OpaqueVerifier(&verifyWrapper{})

func (vw *verifyWrapper) VerifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	if len(vw.wrapped) == 0 {
		return fmt.Errorf("error: verifier had no keys")
	}
	var err error
	for _, v := range vw.wrapped {
		err = v.verifyPayload(payload, signature, alg)
		if err == nil {
			return nil
		}
	}
	return err
}

type keyEncryptWrapper struct {
	kid     string
	wrapped keyEncrypter
	algs    []KeyAlgorithm
}

var _ = OpaqueKeyEncrypter(&keyEncryptWrapper{})

func (kew *keyEncryptWrapper) KeyID() string {
	return kew.kid
}

func (kew *keyEncryptWrapper) Algs() []KeyAlgorithm {
	return kew.algs
}

func (kew *keyEncryptWrapper) encryptKey(cek []byte, alg KeyAlgorithm) (recipientInfo, error) {
	info, err := kew.wrapped.encryptKey(cek, alg)
	if err != nil {
		return recipientInfo{}, err
	}

	return info, nil
}

type keyDecryptWrapper struct {
	wrapped keyDecrypter
}

var _ = OpaqueKeyDecrypter(&keyDecryptWrapper{})

func (kdw *keyDecryptWrapper) DecryptKey(encryptedKey []byte, header Header) ([]byte, error) {
	rawHeader := rawHeader{}

	err := rawHeader.set(headerKeyID, header.KeyID)
	if err != nil {
		return nil, err
	}
	err = rawHeader.set(headerAlgorithm, header.Algorithm)
	if err != nil {
		return nil, err
	}
	err = rawHeader.set(headerNonce, header.Nonce)
	if err != nil {
		return nil, err
	}
	err = rawHeader.set(headerJWK, header.JSONWebKey)
	if err != nil {
		return nil, err
	}
	for k, v := range header.Other {
		err = rawHeader.set(k, v)
		if err != nil {
			return nil, err
		}
	}

	recipient := &recipientInfo{
		encryptedKey: encryptedKey,
	}

	var generator randomKeyGenerator
	cipher := getContentCipher(rawHeader.getEncryption())
	if cipher != nil {
		generator = randomKeyGenerator{
			size: cipher.keySize(),
		}
	}

	return kdw.wrapped.decryptKey(rawHeader, recipient, generator)
}

func TestRoundtripsJWSOpaque(t *testing.T) {
	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupter := func(obj *JSONWebSignature) {}

	for _, alg := range sigAlgs {
		signingKey, verificationKey := GenerateSigningTestKey(alg)

		for i, serializer := range serializers {
			sw := makeOpaqueSigner(t, signingKey, alg)
			vw := makeOpaqueVerifier(t, []interface{}{verificationKey}, alg)

			err := RoundtripJWS(alg, serializer, corrupter, sw, verificationKey, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}

			err = RoundtripJWS(alg, serializer, corrupter, signingKey, vw, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}

			err = RoundtripJWS(alg, serializer, corrupter, sw, vw, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}
		}
	}
}

func makeOpaqueSigner(t *testing.T, signingKey interface{}, alg SignatureAlgorithm) *signWrapper {
	ri, err := makeJWSRecipient(alg, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	return &signWrapper{
		wrapped: ri.signer,
		algs:    []SignatureAlgorithm{alg},
		pk:      ri.publicKey(),
	}
}

func makeOpaqueVerifier(t *testing.T, verificationKey []interface{}, alg SignatureAlgorithm) *verifyWrapper {
	verifiers := []payloadVerifier{}
	for _, vk := range verificationKey {
		verifier, err := newVerifier(vk)
		if err != nil {
			t.Fatal(err)
		}
		verifiers = append(verifiers, verifier)
	}
	return &verifyWrapper{wrapped: verifiers}
}

func TestRoundtripsJWEOpaque(t *testing.T) {
	keyAlgs := []KeyAlgorithm{RSA1_5, RSA_OAEP, RSA_OAEP_256}
	encs := []ContentEncryption{A128GCM, A256GCM, A128CBC_HS256, A256CBC_HS512}

	serializers := []func(*JSONWebEncryption) (string, error){
		func(obj *JSONWebEncryption) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebEncryption) (string, error) { return obj.FullSerialize(), nil },
	}

	for _, alg := range keyAlgs {
		for _, enc := range encs {
			for i, serializer := range serializers {
				ke := makeOpaqueKeyEncrypter(t, &rsaTestKey.PublicKey, alg, "test-kid")
				kd := makeOpaqueKeyDecrypter(t, rsaTestKey, alg)

				encrypter, err := NewEncrypter(enc, Recipient{Algorithm: alg, Key: ke}, nil)
				if err != nil {
					t.Fatal(err, alg, enc, i)
				}

				plaintext := []byte("foo bar baz")
				jwe, err := encrypter.Encrypt(plaintext)
				if err != nil {
					t.Fatal(err, alg, enc, i)
				}

				jwe = jweSerialize(t, serializer, jwe, kd, alg, enc)

				decrypted, err := jwe.Decrypt(kd)
				if err != nil {
					t.Fatal(err, alg, enc, i)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("alg %s enc %s serializer %d: got %q, want %q", alg, enc, i, decrypted, plaintext)
				}
			}
		}
	}
}

func makeOpaqueKeyEncrypter(t *testing.T, signingKey interface{}, alg KeyAlgorithm, kid string) *keyEncryptWrapper {
	rki, err := makeJWERecipient(alg, signingKey)
	if err != nil {
		t.Fatal(err, alg)
	}
	return &keyEncryptWrapper{
		wrapped: rki.keyEncrypter,
		algs:    []KeyAlgorithm{alg},
		kid:     kid,
	}
}

func makeOpaqueKeyDecrypter(t *testing.T, decryptionKey interface{}, alg KeyAlgorithm) *keyDecryptWrapper {
	kd, err := newDecrypter(decryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	return &keyDecryptWrapper{
		wrapped: kd,
	}
}

func TestOpaqueSignerKeyRotation(t *testing.T) {

	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}

	for _, alg := range sigAlgs {
		for i, serializer := range serializers {
			sk1, pk1 := GenerateSigningTestKey(alg)
			sk2, pk2 := GenerateSigningTestKey(alg)

			sw := makeOpaqueSigner(t, sk1, alg)
			sw.pk.KeyID = "first"
			vw := makeOpaqueVerifier(t, []interface{}{pk1, pk2}, alg)

			signer, err := NewSigner(
				SigningKey{Algorithm: alg, Key: sw},
				&SignerOptions{NonceSource: staticNonceSource("test_nonce")},
			)
			if err != nil {
				t.Fatal(err, alg, i)
			}

			jws1, err := signer.Sign([]byte("foo bar baz"))
			if err != nil {
				t.Fatal(err, alg, i)
			}
			jws1 = rtSerialize(t, serializer, jws1, vw, alg)
			if kid := jws1.Signatures[0].Protected.KeyID; kid != "first" {
				t.Errorf("expected kid %q but got %q", "first", kid)
			}

			swNext := makeOpaqueSigner(t, sk2, alg)
			swNext.pk.KeyID = "next"
			sw.wrapped = swNext.wrapped
			sw.pk = swNext.pk

			jws2, err := signer.Sign([]byte("foo bar baz next"))
			if err != nil {
				t.Error(err, alg, i)
			}
			jws2 = rtSerialize(t, serializer, jws2, vw, alg)
			if kid := jws2.Signatures[0].Protected.KeyID; kid != "next" {
				t.Errorf("expected kid %q but got %q", "next", kid)
			}
		}
	}
}

func rtSerialize(t *testing.T, serializer func(*JSONWebSignature) (string, error), sig *JSONWebSignature, vk interface{}, alg SignatureAlgorithm) *JSONWebSignature {
	b, err := serializer(sig)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = ParseSigned(b, []SignatureAlgorithm{alg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sig.Verify(vk); err != nil {
		t.Fatal(err)
	}
	return sig
}

func jweSerialize(t *testing.T,
	serializer func(*JSONWebEncryption) (string, error),
	jwe *JSONWebEncryption,
	d OpaqueKeyDecrypter,
	alg KeyAlgorithm,
	enc ContentEncryption,
) *JSONWebEncryption {
	b, err := serializer(jwe)
	if err != nil {
		t.Fatal(err)
	}
	jwe, err = ParseEncrypted(b, []KeyAlgorithm{alg}, []ContentEncryption{enc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwe.Decrypt(d); err != nil {
		t.Fatal(err)
	}
	return jwe
}

type badSigner struct {
	*ecdsa.PrivateKey
}

func (bs badSigner) Algs() []SignatureAlgorithm {
	return []SignatureAlgorithm{ES256}
}

func (bs badSigner) SignPayload([]byte, SignatureAlgorithm) ([]byte, error) {
	panic("Shouldn't be called in this test")
}

func (bs badSigner) Public() *JSONWebKey {
	return &JSONWebKey{
		Key:   bs.PrivateKey,
		KeyID: "BS",
	}
}

// TestOpaqueSignerNonPublic ensures a private key returned in Public() doesn't end up in an embedded JWK
func TestOpaqueSignerNonPublic(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var os OpaqueSigner = badSigner{key}
	_, err := NewSigner(SigningKey{Algorithm: ES256, Key: os}, &SignerOptions{EmbedJWK: true})
	if !errors.Is(err, ErrNotPublic) {
		t.Fatal("Expected ErrNotPublic when using BadSigner")
	}
}

type publicKeySigner struct {
	alg SignatureAlgorithm
	key interface{}
}

func (ps publicKeySigner) Algs() []SignatureAlgorithm {
	return []SignatureAlgorithm{ps.alg}
}

func (ps publicKeySigner) SignPayload([]byte, SignatureAlgorithm) ([]byte, error) {
	return []byte("signature"), nil
}

func (ps publicKeySigner) Public() *JSONWebKey {
	return &JSONWebKey{
		Key:   ps.key,
		KeyID: "PS",
	}
}

// customPublicKey is a public key type unknown to go-jose.
type customPublicKey []byte

func assertOpaqueSignerPublicKeyTypes(t *testing.T, alg SignatureAlgorithm, key any, wantErr error) {
	t.Helper()

	signer, err := NewSigner(SigningKey{
		Algorithm: alg,
		Key:       publicKeySigner{alg, key},
	}, &SignerOptions{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewSigner() error = %v, want %v", err, wantErr)
	}
	if err != nil {
		return
	}

	jws, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(jws.FullSerialize(), []SignatureAlgorithm{alg})
	if err != nil {
		t.Fatal(err)
	}
	if kid := parsed.Signatures[0].Header.KeyID; kid != "PS" {
		t.Errorf("kid = %q, want %q", kid, "PS")
	}
}

func TestOpaqueSignerPublicKeyTypes(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		alg     SignatureAlgorithm
		key     any
		wantErr error
	}{
		{"ecdsa private", ES256, ecKey, ErrNotPublic},
		{"rsa private", RS256, rsaKey, ErrNotPublic},
		{"ed25519 private", EdDSA, edKey, ErrNotPublic},
		{"ecdsa public", ES256, &ecKey.PublicKey, nil},
		{"rsa public", RS256, &rsaKey.PublicKey, nil},
		{"ed25519 public", EdDSA, edPub, nil},
		{"custom public", SignatureAlgorithm("CustomDSA"), customPublicKey("public key"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOpaqueSignerPublicKeyTypes(t, tt.alg, tt.key, tt.wantErr)
		})
	}
}
