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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

func TestEd25519(t *testing.T) {
	_, err := newEd25519Signer("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	enc := new(edEncrypterVerifier)
	enc.publicKey = ed25519PublicKey
	err = enc.verifyPayload([]byte{}, []byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	dec := new(edDecrypterSigner)
	dec.privateKey = ed25519PrivateKey
	_, err = dec.signPayload([]byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	sig, err := dec.signPayload([]byte("This is a test"), "EdDSA")
	if err != nil {
		t.Error("should not error trying to sign payload")
	}
	if sig.Signature == nil {
		t.Error("Check the signature")
	}
	err = enc.verifyPayload([]byte("This is a test"), sig.Signature, "EdDSA")
	if err != nil {
		t.Error("should not error trying to verify payload")
	}

	err = enc.verifyPayload([]byte("This is test number 2"), sig.Signature, "EdDSA")
	if err == nil {
		t.Error("should not error trying to verify payload")
	}
}

func TestInvalidAlgorithmsRSA(t *testing.T) {
	_, err := newRSARecipient("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	_, err = newRSASigner("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &rsaTestKey.PublicKey
	_, err = enc.encryptKey([]byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	err = enc.verifyPayload([]byte{}, []byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	dec := new(rsaDecrypterSigner)
	dec.privateKey = rsaTestKey
	_, err = dec.decrypt(make([]byte, 256), "XYZ", randomKeyGenerator{size: 16})
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	_, err = dec.signPayload([]byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}
}

type failingKeyGenerator struct{}

func (ctx failingKeyGenerator) keySize() int {
	return 0
}

func (ctx failingKeyGenerator) genKey() ([]byte, rawHeader, error) {
	return nil, rawHeader{}, errors.New("failed to generate key")
}

func TestPKCSKeyGeneratorFailure(t *testing.T) {
	dec := new(rsaDecrypterSigner)
	dec.privateKey = rsaTestKey
	generator := failingKeyGenerator{}
	_, err := dec.decrypt(make([]byte, 256), RSA1_5, generator)
	if err != ErrCryptoFailure {
		t.Error("should return error on invalid algorithm")
	}
}

func TestInvalidAlgorithmsEC(t *testing.T) {
	_, err := newECDHRecipient("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	_, err = newECDSASigner("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	enc := new(ecEncrypterVerifier)
	enc.publicKey = &ecTestKey256.PublicKey
	_, err = enc.encryptKey([]byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}
}

func TestInvalidECKeyGen(t *testing.T) {
	gen := ecKeyGenerator{
		size:      16,
		algID:     "A128GCM",
		publicKey: &ecTestKey256.PublicKey,
	}

	if gen.keySize() != 16 {
		t.Error("ec key generator reported incorrect key size")
	}

	_, _, err := gen.genKey()
	if err != nil {
		t.Error("ec key generator failed to generate key", err)
	}
}

func TestInvalidECDecrypt(t *testing.T) {
	dec := ecDecrypterSigner{
		privateKey: ecTestKey256,
	}

	generator := randomKeyGenerator{size: 16}

	recipient := recipientInfo{
		// decryptKey will error out before the contents here matter
		encryptedKey: []byte("not used"),
	}
	// Missing epk header
	headers := rawHeader{}

	if err := headers.set(headerAlgorithm, ECDH_ES); err != nil {
		t.Fatal(err)
	}

	want := "go-jose/go-jose: missing epk header"
	_, err := dec.decryptKey(headers, &recipient, generator)
	if err == nil {
		t.Error("ec decrypter accepted object with missing epk header")
	} else if err.Error() != want {
		t.Errorf("decryptKey with missing epk header: got %q, want %q", err, want)
	}

	// Invalid epk header
	invalid := json.RawMessage("invalid")
	headers["epk"] = &invalid

	want = "go-jose/go-jose: invalid epk header"
	_, err = dec.decryptKey(headers, &recipient, generator)
	if err == nil {
		t.Error("ec decrypter accepted object with invalid epk header")
	} else if err.Error() != want {
		t.Errorf("decryptKey with invalid epk header: got %q, want %q", err, want)
	}
}

func TestDecryptWithIncorrectSize(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}

	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	payload := make([]byte, 254)
	_, err = dec.decrypt(payload, RSA1_5, keygen)
	if err == nil {
		t.Error("Invalid payload size should return error")
	}

	payload = make([]byte, 257)
	_, err = dec.decrypt(payload, RSA1_5, keygen)
	if err == nil {
		t.Error("Invalid payload size should return error")
	}
}

func TestPKCSDecryptNeverFails(t *testing.T) {
	// We don't want RSA-PKCS1 v1.5 decryption to ever fail, in order to prevent
	// side-channel timing attacks (Bleichenbacher attack in particular).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}

	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	for i := 1; i < 50; i++ {
		payload := make([]byte, 256)
		_, err := io.ReadFull(rand.Reader, payload)
		if err != nil {
			t.Error("Unable to get random data:", err)
			return
		}
		_, err = dec.decrypt(payload, RSA1_5, keygen)
		if err != nil {
			t.Error("PKCS1v1.5 decrypt should never fail:", err)
			return
		}
	}
}

func BenchmarkPKCSDecryptWithValidPayloads(b *testing.B) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &priv.PublicKey
	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(32)

	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext := make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, plaintext)
		if err != nil {
			panic(err)
		}

		ciphertext, err := enc.encrypt(plaintext, RSA1_5)
		if err != nil {
			panic(err)
		}

		keygen := randomKeyGenerator{
			size: aes.keySize(),
		}

		b.StartTimer()
		_, err = dec.decrypt(ciphertext, RSA1_5, keygen)
		b.StopTimer()
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkPKCSDecryptWithInvalidPayloads(b *testing.B) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &priv.PublicKey
	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext := make([]byte, 16)
		_, err = io.ReadFull(rand.Reader, plaintext)
		if err != nil {
			panic(err)
		}

		ciphertext, err := enc.encrypt(plaintext, RSA1_5)
		if err != nil {
			panic(err)
		}

		// Do some simple scrambling
		ciphertext[128] ^= 0xFF

		b.StartTimer()
		_, err = dec.decrypt(ciphertext, RSA1_5, keygen)
		b.StopTimer()
		if err != nil {
			panic(err)
		}
	}
}

func TestInvalidEllipticCurve(t *testing.T) {
	signer256 := ecDecrypterSigner{privateKey: ecTestKey256}
	signer384 := ecDecrypterSigner{privateKey: ecTestKey384}
	signer521 := ecDecrypterSigner{privateKey: ecTestKey521}

	_, err := signer256.signPayload([]byte{}, ES384)
	if err == nil {
		t.Error("should not generate ES384 signature with P-256 key")
	}
	_, err = signer256.signPayload([]byte{}, ES512)
	if err == nil {
		t.Error("should not generate ES512 signature with P-256 key")
	}
	_, err = signer384.signPayload([]byte{}, ES256)
	if err == nil {
		t.Error("should not generate ES256 signature with P-384 key")
	}
	_, err = signer384.signPayload([]byte{}, ES512)
	if err == nil {
		t.Error("should not generate ES512 signature with P-384 key")
	}
	_, err = signer521.signPayload([]byte{}, ES256)
	if err == nil {
		t.Error("should not generate ES256 signature with P-521 key")
	}
	_, err = signer521.signPayload([]byte{}, ES384)
	if err == nil {
		t.Error("should not generate ES384 signature with P-521 key")
	}
}

func TestInvalidEllipticCurveVerify(t *testing.T) {
	payload := []byte("payload")

	// Mixed signature: we're signing with P-256, but the hash is SHA-384. This
	// allows us to trigger the "mismatched curve" code instead of the "mismatched hash"
	// code when we try to verify using the JOSE alg ES384.
	hash384 := sha512.Sum384(payload)
	r, s, err := ecdsa.Sign(rand.Reader, ecTestKey256, hash384[:])
	if err != nil {
		t.Fatal(err)
	}

	// Make a fake ES384 signature by taking the r and s from the P-256 signature
	// and padding them out with zeroes.
	newSignature := make([]byte, 96)
	// FillBytes will zero-extend the 32-byte `r` and `s` values to fill the space available.
	r.FillBytes(newSignature[:48])
	s.FillBytes(newSignature[48:])

	verifier256 := ecEncrypterVerifier{publicKey: &ecTestKey256.PublicKey}
	err = verifier256.verifyPayload(payload, newSignature, ES384)
	if err == nil || !strings.Contains(err.Error(), "different algorithm") {
		t.Fatalf("verifying payload: expected error containing 'different algorithm', got %v", err)
	}

	// Mixed signature: we're signing with P-384, but the hash is SHA-512. This
	// allows us to trigger the "mismatched curve" code instead of the "mismatched hash"
	// code when we try to verify using the JOSE alg ES512.
	hash512 := sha512.Sum512(payload)
	r, s, err = ecdsa.Sign(rand.Reader, ecTestKey384, hash512[:])
	if err != nil {
		t.Fatal(err)
	}

	// Make a fake ES512 signature by taking the r and s from the P-384 signature
	// and padding them out with zeroes.
	newSignature = make([]byte, 132)
	// FillBytes will zero-extend the 48-byte `r` and `s` values to fill the space available.
	r.FillBytes(newSignature[:66])
	s.FillBytes(newSignature[66:])

	verifier384 := ecEncrypterVerifier{publicKey: &ecTestKey384.PublicKey}
	err = verifier384.verifyPayload(payload, newSignature, ES512)
	if err == nil || !strings.Contains(err.Error(), "different algorithm") {
		t.Fatalf("verifying payload: expected error containing 'different algorithm', got %v", err)
	}
}

func TestInvalidECPublicKey(t *testing.T) {
	// Invalid key
	invalid := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     fromBase64Int("MTEx"),
			Y:     fromBase64Int("MTEx"),
		},
		D: fromBase64Int("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"),
	}

	recipient := recipientInfo{
		// encryptedKey must be non-empty to pass initial checks, but the actual
		// bytes don't matter because we'll error out before using them.
		encryptedKey: []byte("not used"),
	}

	headers := rawHeader{}

	if err := headers.set(headerAlgorithm, ECDH_ES); err != nil {
		t.Fatal(err)
	}

	if err := headers.set(headerEPK, &JSONWebKey{Key: &invalid.PublicKey}); err != nil {
		t.Fatal(err)
	}

	dec := ecDecrypterSigner{
		privateKey: ecTestKey256,
	}

	_, err := dec.decryptKey(headers, &recipient, randomKeyGenerator{size: 16})
	if err == nil {
		t.Fatal("decrypter accepted JWS with invalid ECDH public key")
	}

	want := "go-jose/go-jose: invalid epk header"
	if err.Error() != want {
		t.Errorf("decryptKey with invalid ECDH public key: got %q, want %q", err, want)
	}
}

func TestInvalidAlgorithmEC(t *testing.T) {
	err := ecEncrypterVerifier{publicKey: &ecTestKey256.PublicKey}.verifyPayload([]byte{}, []byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Fatal("should not accept invalid/unsupported algorithm")
	}
}
