package fuzz

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

var allSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.HS256, jose.HS384, jose.HS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// Merge A: FuzzJWSParse consolidates FuzzParseSigned, FuzzParseSignedCompact, and FuzzParseSignedJSON.
func FuzzJWSParse(f *testing.F) {
	// Seeds from FuzzParseSigned
	f.Add("eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature")
	f.Add(`{"payload":"dGVzdA","signatures":[{"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"AAAA"}]}`)
	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJIUzI1NiIsImtpZCI6Im15a2V5Iiwibm9uY2UiOiJhYmMiLCJjdHkiOiJKV1QiLCJ0eXAiOiJKV1QiLCJqd2siOnsia3R5Ijoib2N0IiwiayI6IkFBIn19.dGVzdA.AAAA")
	f.Add("eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlCIl19.dGVzdA.AAAA")
	f.Add("eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9.dGVzdA.AAAA")
	f.Add("eyJhbGciOiJIUzI1NiIsImNyaXQiOlsidW5rbm93biJdfQ.dGVzdA.AAAA")
	// Seeds from FuzzParseSignedJSON
	f.Add(`{"payload":"dGVzdA","protected":"eyJhbGciOiJFUzI1NiJ9","signature":"AAAA"}`)
	f.Add("{}")
	f.Add(`{"payload":"dGVzdA","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"mykey","nonce":"abc"},"signature":"AAAA"}]}`)
	// Regression 5348b9a: crit header in unprotected header must be rejected
	f.Add(`{"payload":"dGVzdA","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"crit":["b64"],"b64":false},"signature":"AAAA"}]}`)
	// Regression 455da8c: base64 with = padding must be rejected
	f.Add("eyJhbGciOiJFUzI1NiJ9=.dGVzdA.AAAA")
	// Regression 99b346c: excessive dots must not cause unbounded allocation
	f.Add("eyJhbGciOiJFUzI1NiJ9.dGVzdA.AAAA..........................................................")
	f.Fuzz(func(t *testing.T, data string) {
		jose.ParseSigned(data, allSignatureAlgorithms)
		jose.ParseSignedCompact(data, allSignatureAlgorithms)
		jose.ParseSignedJSON(data, allSignatureAlgorithms)
	})
}

// FuzzParseDetached is kept standalone — different signature (string, []byte).
func FuzzParseDetached(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiJ9..signature", []byte("payload"))
	f.Add("a..c", []byte("test"))
	f.Fuzz(func(t *testing.T, sig string, payload []byte) {
		jose.ParseDetached(sig, payload, allSignatureAlgorithms)
	})
}

// Merge B: FuzzJWSSerialize consolidates FuzzJWSCompactSerializeRoundTrip,
// FuzzJWSDetachedCompactSerialize, FuzzJWSFullSerialize, and FuzzJWSUnsafePayloadWithoutVerification.
func FuzzJWSSerialize(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature")
	f.Add(`{"payload":"dGVzdA","protected":"eyJhbGciOiJFUzI1NiJ9","signature":"AAAA"}`)
	// Seed with a real signed JWS
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)
	if signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey}, nil); err == nil {
		if sig, err := signer.Sign([]byte("test")); err == nil {
			if s, err := sig.CompactSerialize(); err == nil {
				f.Add(s)
			}
		}
	}
	// Seed with a real multi-signature JWS for FullSerialize multi-sig branch
	hmacKey2 := make([]byte, 64)
	rand.Read(hmacKey2)
	multiSigner, _ := jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: jose.HS256, Key: hmacKey},
		{Algorithm: jose.HS384, Key: hmacKey2},
	}, nil)
	if multiSigner != nil {
		if sig, err := multiSigner.Sign([]byte("multi")); err == nil {
			f.Add(sig.FullSerialize())
		}
	}
	f.Fuzz(func(t *testing.T, data string) {
		sig, err := jose.ParseSigned(data, allSignatureAlgorithms)
		if err != nil {
			return
		}
		sig.CompactSerialize()
		sig.DetachedCompactSerialize()
		sig.FullSerialize()
		sig.UnsafePayloadWithoutVerification()
	})
}

// Merge C: FuzzJWSVerifyAll consolidates FuzzJWSVerify and FuzzJWSVerifyMulti.
func FuzzJWSVerifyAll(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	// Wrap keys as JWK/JWKS for exercising tryJWKS and newVerifier(JSONWebKey) paths
	rsaJWK := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rsa-kid"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{rsaJWK}}

	// Seeds from FuzzJWSVerify
	f.Add("eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature")
	if signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey}, nil); err == nil {
		if sig, err := signer.Sign([]byte("test")); err == nil {
			if s, err := sig.CompactSerialize(); err == nil {
				f.Add(s)
			}
		}
	}
	// Seed with embedded JWK header to exercise getJWK (shared.go:323)
	if signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ecKey}, &jose.SignerOptions{EmbedJWK: true}); err == nil {
		if sig, err := signer.Sign([]byte("jwk-embed")); err == nil {
			if s, err := sig.CompactSerialize(); err == nil {
				f.Add(s)
			}
		}
	}
	// Seeds from FuzzJWSVerifyMulti
	f.Add(`{"payload":"dGVzdA","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"AAAA"}]}`)
	multiSigner, _ := jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: jose.HS256, Key: hmacKey},
		{Algorithm: jose.HS384, Key: hmacKey},
	}, nil)
	if multiSigner != nil {
		if sig, err := multiSigner.Sign([]byte("multi")); err == nil {
			f.Add(sig.FullSerialize())
		}
	}
	f.Fuzz(func(t *testing.T, data string) {
		sig, err := jose.ParseSigned(data, allSignatureAlgorithms)
		if err != nil {
			return
		}
		// Try verification with each key type — we only care about panics.
		sig.Verify(&rsaKey.PublicKey)
		sig.Verify(&ecKey.PublicKey)
		sig.Verify(edKey.Public())
		sig.Verify(hmacKey)
		// Also exercise JSONWebKey and JSONWebKeySet paths in newVerifier/tryJWKS
		sig.Verify(rsaJWK)
		sig.Verify(&rsaJWK)
		sig.Verify(jwks)
		sig.Verify(&jwks)
		// VerifyMulti
		sig.VerifyMulti(hmacKey)
	})
}

// Merge D: FuzzJWSDetachedVerifyAll consolidates FuzzJWSDetachedVerify and FuzzJWSDetachedVerifyMulti.
func FuzzJWSDetachedVerifyAll(f *testing.F) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	// Seeds from FuzzJWSDetachedVerify
	f.Add("eyJhbGciOiJFZERTQSJ9..signature", []byte("payload"))
	// Seeds from FuzzJWSDetachedVerifyMulti
	f.Add(`{"payload":"dGVzdA","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"AAAA"}]}`, []byte("test"))
	multiSigner, _ := jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: jose.HS256, Key: hmacKey},
		{Algorithm: jose.HS384, Key: hmacKey},
	}, nil)
	if multiSigner != nil {
		if sig, err := multiSigner.Sign([]byte("multi")); err == nil {
			f.Add(sig.FullSerialize(), []byte("multi"))
		}
	}
	f.Fuzz(func(t *testing.T, data string, payload []byte) {
		// DetachedVerify path
		parsed, err := jose.ParseDetached(data, payload, allSignatureAlgorithms)
		if err == nil {
			parsed.DetachedVerify(payload, edKey.Public())
		}
		// DetachedVerifyMulti path
		sig, err := jose.ParseSigned(data, allSignatureAlgorithms)
		if err == nil {
			sig.DetachedVerifyMulti(payload, hmacKey)
		}
	})
}

// Merge E: FuzzJWSConstructionOpaque consolidates FuzzNewSignerOpaque and FuzzJWSVerifyWithOpaqueVerifier.

// opaqueVerifierImpl wraps a real key to exercise the OpaqueVerifier path.
type opaqueVerifierImpl struct {
	key interface{}
}

func (v *opaqueVerifierImpl) VerifyPayload(payload []byte, signature []byte, alg jose.SignatureAlgorithm) error {
	// Delegate to a real verify by signing and comparing — but for fuzz, just
	// always return nil to exercise the code path.
	return nil
}

func FuzzJWSConstructionOpaque(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	f.Add([]byte("test payload"), uint8(0))
	f.Add([]byte("test payload"), uint8(1))
	f.Add([]byte("test payload"), uint8(2))
	f.Fuzz(func(t *testing.T, payload []byte, keyType uint8) {
		var opaque jose.OpaqueSigner
		var alg jose.SignatureAlgorithm
		var pub interface{}

		switch keyType % 3 {
		case 0:
			opaque = cryptosigner.Opaque(rsaKey)
			alg = jose.RS256
			pub = &rsaKey.PublicKey
		case 1:
			opaque = cryptosigner.Opaque(ecKey)
			alg = jose.ES256
			pub = &ecKey.PublicKey
		case 2:
			opaque = cryptosigner.Opaque(edKey)
			alg = jose.EdDSA
			pub = edKey.Public()
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, nil)
		if err != nil {
			return
		}
		sig, err := signer.Sign(payload)
		if err != nil {
			return
		}
		// Verify with real public key
		sig.Verify(pub)
		// Verify with OpaqueVerifier to exercise opaque.go verifyPayload
		verifier := &opaqueVerifierImpl{key: pub}
		sig.Verify(verifier)
	})
}

// FuzzNewSignerAllAlgorithms exercises RSA, ECDSA, Ed25519, and PSS signing
// paths in asymmetric.go (newRSASigner, newECDSASigner, signPayload, verifyPayload).
// Also covers the former FuzzNewSigner (HMAC round-trip, algIdx=10).
func FuzzNewSignerAllAlgorithms(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKeyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecKeyP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	// Seed each algorithm index
	for i := uint8(0); i < 13; i++ {
		f.Add([]byte("test payload"), i)
	}
	// Seed from former FuzzNewSigner (HMAC round-trip)
	f.Add([]byte("test payload"), uint8(10))
	f.Fuzz(func(t *testing.T, payload []byte, algIdx uint8) {
		type sigConfig struct {
			alg jose.SignatureAlgorithm
			key interface{}
			pub interface{}
		}

		configs := []sigConfig{
			{jose.RS256, rsaKey, &rsaKey.PublicKey},
			{jose.RS384, rsaKey, &rsaKey.PublicKey},
			{jose.RS512, rsaKey, &rsaKey.PublicKey},
			{jose.PS256, rsaKey, &rsaKey.PublicKey},
			{jose.PS384, rsaKey, &rsaKey.PublicKey},
			{jose.PS512, rsaKey, &rsaKey.PublicKey},
			{jose.ES256, ecKeyP256, &ecKeyP256.PublicKey},
			{jose.ES384, ecKeyP384, &ecKeyP384.PublicKey},
			{jose.ES512, ecKeyP521, &ecKeyP521.PublicKey},
			{jose.EdDSA, edKey, edKey.Public()},
			{jose.HS256, hmacKey, hmacKey},
			{jose.HS384, hmacKey, hmacKey},
			{jose.HS512, hmacKey, hmacKey},
		}

		cfg := configs[int(algIdx)%len(configs)]
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: cfg.alg, Key: cfg.key}, nil)
		if err != nil {
			return
		}
		sig, err := signer.Sign(payload)
		if err != nil {
			return
		}
		_, err = sig.Verify(cfg.pub)
		if err != nil {
			t.Fatalf("verify failed for %s: %v", cfg.alg, err)
		}
	})
}

// FuzzNewSignerInvalidCombos exercises error branches in asymmetric/symmetric
// constructors by passing mismatched algorithm+key combos.
func FuzzNewSignerInvalidCombos(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	type combo struct {
		alg jose.SignatureAlgorithm
		key interface{}
	}
	// Intentionally mismatched — these should all fail in the constructor
	mismatches := []combo{
		{jose.ES256, rsaKey},  // EC alg + RSA key
		{jose.RS256, ecKey},   // RSA alg + EC key
		{jose.EdDSA, rsaKey},  // EdDSA alg + RSA key
		{jose.HS256, rsaKey},  // HMAC alg + RSA key
		{jose.RS256, hmacKey}, // RSA alg + HMAC key
		{jose.ES256, edKey},   // EC alg + Ed25519 key
		{jose.EdDSA, ecKey},   // EdDSA alg + EC key
		{jose.RS256, nil},     // nil key
	}

	for i := range mismatches {
		f.Add(uint8(i))
	}
	f.Fuzz(func(t *testing.T, idx uint8) {
		m := mismatches[int(idx)%len(mismatches)]
		// We expect these to fail — just make sure they don't panic
		jose.NewSigner(jose.SigningKey{Algorithm: m.alg, Key: m.key}, nil)
	})
}

// staticNonceSource returns a fixed nonce for testing.
type staticNonceSource string

func (s staticNonceSource) Nonce() (string, error) { return string(s), nil }

// FuzzNewSignerWithOptions exercises WithHeader, WithContentType, WithType,
// WithCritical, WithBase64, Options(), EmbedJWK, and NonceSource paths.
func FuzzNewSignerWithOptions(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	f.Add([]byte("test"), "JWT", "custom-header-val", true, false, false)
	f.Add([]byte("payload"), "at+jwt", "", false, false, false)
	f.Add([]byte("test"), "JWT", "", true, true, true)  // embedJWK + nonce
	f.Add([]byte("test"), "", "", true, true, false)     // embedJWK without nonce
	f.Add([]byte("test"), "", "", true, false, true)     // nonce without embedJWK
	f.Fuzz(func(t *testing.T, payload []byte, typ string, customVal string, useB64 bool, embedJWK bool, useNonce bool) {
		var key interface{}
		var alg jose.SignatureAlgorithm
		var verifyKey interface{}
		if embedJWK {
			// EmbedJWK needs an asymmetric key (publicKey func must return non-nil)
			key = rsaKey
			alg = jose.RS256
			verifyKey = &rsaKey.PublicKey
		} else {
			key = hmacKey
			alg = jose.HS256
			verifyKey = hmacKey
		}

		opts := &jose.SignerOptions{EmbedJWK: embedJWK}
		if useNonce {
			opts.NonceSource = staticNonceSource("test-nonce")
		}
		if typ != "" {
			opts = opts.WithType(jose.ContentType(typ))
		}
		if customVal != "" {
			opts = opts.WithHeader("x-custom", customVal)
		}
		if !useB64 {
			opts = opts.WithBase64(false)
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
		if err != nil {
			return
		}
		_ = signer.Options()
		sig, err := signer.Sign(payload)
		if err != nil {
			return
		}
		if useB64 {
			sig.Verify(verifyKey)
		} else {
			sig.DetachedVerify(payload, verifyKey)
		}
		sig.CompactSerialize()
		sig.DetachedCompactSerialize()
		sig.FullSerialize()
	})
}

// FuzzNewSignerWithJWK exercises the newJWKSigner path in signing.go,
// including the publicKey embedding and JWKS verification paths.
func FuzzNewSignerWithJWK(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	f.Add([]byte("test payload"), uint8(0))
	f.Add([]byte("test payload"), uint8(1))
	f.Add([]byte("test payload"), uint8(2))
	f.Fuzz(func(t *testing.T, payload []byte, keyIdx uint8) {
		var jwk jose.JSONWebKey
		var alg jose.SignatureAlgorithm
		var verifyKey interface{}

		switch keyIdx % 3 {
		case 0:
			jwk = jose.JSONWebKey{Key: rsaKey, KeyID: "rsa-kid"}
			alg = jose.RS256
			verifyKey = &rsaKey.PublicKey
		case 1:
			jwk = jose.JSONWebKey{Key: ecKey, KeyID: "ec-kid"}
			alg = jose.ES256
			verifyKey = &ecKey.PublicKey
		case 2:
			jwk = jose.JSONWebKey{Key: hmacKey, KeyID: "hmac-kid"}
			alg = jose.HS256
			verifyKey = hmacKey
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jwk}, nil)
		if err != nil {
			return
		}
		sig, err := signer.Sign(payload)
		if err != nil {
			return
		}
		// Verify directly
		sig.Verify(verifyKey)
		// Verify via JWK
		pubJWK := jose.JSONWebKey{Key: verifyKey, KeyID: jwk.KeyID}
		sig.Verify(pubJWK)
		// Verify via JWKS (exercises tryJWKS with kid matching)
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
		sig.Verify(jwks)
	})
}
