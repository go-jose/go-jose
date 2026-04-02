package fuzz

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

func FuzzCryptoSigner(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKeyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecKeyP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	for i := uint8(0); i < 8; i++ {
		f.Add([]byte("test payload"), i)
	}
	f.Add([]byte("hello world"), uint8(6))
	f.Fuzz(func(t *testing.T, payload []byte, keyType uint8) {
		var signer jose.OpaqueSigner
		var alg jose.SignatureAlgorithm
		var publicKey crypto.PublicKey

		switch keyType % 8 {
		case 0:
			signer = cryptosigner.Opaque(rsaKey)
			alg = jose.RS256
			publicKey = &rsaKey.PublicKey
		case 1:
			signer = cryptosigner.Opaque(rsaKey)
			alg = jose.PS256
			publicKey = &rsaKey.PublicKey
		case 2:
			signer = cryptosigner.Opaque(rsaKey)
			alg = jose.RS384
			publicKey = &rsaKey.PublicKey
		case 3:
			signer = cryptosigner.Opaque(ecKeyP256)
			alg = jose.ES256
			publicKey = &ecKeyP256.PublicKey
		case 4:
			signer = cryptosigner.Opaque(ecKeyP384)
			alg = jose.ES384
			publicKey = &ecKeyP384.PublicKey
		case 5:
			signer = cryptosigner.Opaque(ecKeyP521)
			alg = jose.ES512
			publicKey = &ecKeyP521.PublicKey
		case 6:
			signer = cryptosigner.Opaque(edKey)
			alg = jose.EdDSA
			publicKey = edKey.Public()
		case 7:
			signer = cryptosigner.Opaque(rsaKey)
			alg = jose.PS512
			publicKey = &rsaKey.PublicKey
		}

		// Check Public() doesn't panic
		pub := signer.Public()
		if pub == nil {
			return
		}

		// Check Algs() doesn't panic
		algs := signer.Algs()
		if len(algs) == 0 {
			return
		}

		// SignPayload with fuzzed payload
		signer.SignPayload(payload, alg)

		// Sign-verify round-trip via jose.NewSigner
		joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signer}, nil)
		if err != nil {
			return
		}
		sig, err := joseSigner.Sign(payload)
		if err != nil {
			return
		}
		result, err := sig.Verify(publicKey)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}
		if string(result) != string(payload) {
			t.Fatalf("round-trip mismatch")
		}
	})
}
