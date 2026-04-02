package fuzz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

var allKeyAlgorithms = []jose.KeyAlgorithm{
	jose.ED25519,
	jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256,
	jose.A128KW, jose.A192KW, jose.A256KW,
	jose.DIRECT,
	jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
	jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
	jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW,
}

var allContentEncryption = []jose.ContentEncryption{
	jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512,
	jose.A128GCM, jose.A192GCM, jose.A256GCM,
}

// --- Merge A: FuzzJWEParse (merges FuzzParseEncrypted + FuzzParseEncryptedCompact + FuzzParseEncryptedJSON) ---

func FuzzJWEParse(f *testing.F) {
	// Seeds from FuzzParseEncrypted
	f.Add("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a.b.c.d")
	f.Add(`{"protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"a","iv":"b","ciphertext":"c","tag":"d"}`)
	f.Add("")
	// {"alg":"A128KW","enc":"A128GCM","kid":"mykey","cty":"JWT","typ":"JWT","zip":"DEF"}
	f.Add("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoibXlrZXkiLCJjdHkiOiJKV1QiLCJ0eXAiOiJKV1QiLCJ6aXAiOiJERUYifQ.a.b.c.d")
	// Seeds from FuzzParseEncryptedCompact
	f.Add("a.b.c.d.e")
	// Seeds from FuzzParseEncryptedJSON
	f.Add("{}")
	// Seed with both protected and unprotected headers for merge/isSet coverage
	f.Add(`{"protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"kid":"mykey","cty":"JWT"},"encrypted_key":"a","iv":"b","ciphertext":"c","tag":"d"}`)
	// Seed with empty kid in protected and non-empty in unprotected (isSet empty-string path)
	f.Add(`{"protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiIn0","unprotected":{"kid":"fallback"},"encrypted_key":"a","iv":"b","ciphertext":"c","tag":"d"}`)
	// Regression e976912: enc validation checked alg instead of enc; {"enc":"A256GCM"} with no alg
	f.Add("eyJlbmMiOiJBMjU2R0NNIn0.a.b.c.d")
	// Regression 455da8c: base64 with = padding must be rejected
	f.Add("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0=.a.b.c.d")
	// Regression 99b346c: excessive dots must not cause unbounded allocation
	f.Add("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a.b.c.d..........................................................")
	f.Fuzz(func(t *testing.T, data string) {
		jose.ParseEncrypted(data, allKeyAlgorithms, allContentEncryption)
		jose.ParseEncryptedCompact(data, allKeyAlgorithms, allContentEncryption)
		jose.ParseEncryptedJSON(data, allKeyAlgorithms, allContentEncryption)
	})
}

// --- Merge B: FuzzJWESerialize (merges FuzzJWECompactSerializeRoundTrip + FuzzJWEFullSerialize + FuzzJWEGetAuthData) ---

func FuzzJWESerialize(f *testing.F) {
	f.Add("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a.b.c.d")
	f.Add(`{"protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"a","iv":"b","ciphertext":"c","tag":"d"}`)
	// Seed with real JWEs for successful parse->serialize paths
	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	enc, _ := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
		Algorithm: jose.A128KW, Key: aesKey,
	}, nil)
	if enc != nil {
		jwe, _ := enc.Encrypt([]byte("test"))
		if jwe != nil {
			if s, err := jwe.CompactSerialize(); err == nil {
				f.Add(s)
			}
			f.Add(jwe.FullSerialize())
		}
		// Also seed with EncryptWithAuthData for AAD coverage
		jweAAD, _ := enc.EncryptWithAuthData([]byte("test"), []byte("extra-aad"))
		if jweAAD != nil {
			f.Add(jweAAD.FullSerialize())
		}
	}
	f.Fuzz(func(t *testing.T, data string) {
		enc, err := jose.ParseEncrypted(data, allKeyAlgorithms, allContentEncryption)
		if err != nil {
			return
		}
		enc.CompactSerialize()
		enc.FullSerialize()
		enc.GetAuthData()
	})
}

// --- Merge C: FuzzJWEDecryptAll (merges FuzzJWEDecrypt + FuzzJWEDecryptMulti) ---

func FuzzJWEDecryptAll(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	// JWK/JWKS for tryJWKS paths
	rsaJWK := jose.JSONWebKey{Key: rsaKey, KeyID: "rsa-kid"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{rsaJWK}}

	// Seeds from FuzzJWEDecrypt
	f.Add("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a.b.c.d")
	// Seed with KW algorithm and empty encrypted_key — triggers KeyUnwrap with empty input
	f.Add("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA")
	// Seed with a real AES-KW encrypted JWE
	if enc, err := jose.NewEncrypter(jose.A128CBC_HS256, jose.Recipient{
		Algorithm: jose.A128KW, Key: aesKey,
	}, nil); err == nil {
		if jwe, err := enc.Encrypt([]byte("test")); err == nil {
			if s, err := jwe.CompactSerialize(); err == nil {
				f.Add(s)
			}
		}
	}
	// Seed with ECDH-ES encrypted JWE to exercise ecDecrypterSigner.decryptKey
	if enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
		Algorithm: jose.ECDH_ES, Key: &ecKey.PublicKey,
	}, nil); err == nil {
		if jwe, err := enc.Encrypt([]byte("ecdh-es test")); err == nil {
			if s, err := jwe.CompactSerialize(); err == nil {
				f.Add(s)
			}
		}
	}
	// Seed with ECDH-ES+A128KW to exercise key-unwrap path in ecDecrypterSigner.decryptKey
	if enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
		Algorithm: jose.ECDH_ES_A128KW, Key: &ecKey.PublicKey,
	}, nil); err == nil {
		if jwe, err := enc.Encrypt([]byte("ecdh-kw test")); err == nil {
			if s, err := jwe.CompactSerialize(); err == nil {
				f.Add(s)
			}
		}
	}
	// Seeds from FuzzJWEDecryptMulti
	f.Add(`{"protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","recipients":[{"encrypted_key":"a"}],"iv":"b","ciphertext":"c","tag":"d"}`)
	// Seed with KW algorithm and empty encrypted_key in multi-recipient format
	f.Add(`{"protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","recipients":[{"encrypted_key":""}],"iv":"b","ciphertext":"c","tag":"d"}`)

	f.Fuzz(func(t *testing.T, data string) {
		enc, err := jose.ParseEncrypted(data, allKeyAlgorithms, allContentEncryption)
		if err != nil {
			return
		}
		// Try Decrypt with each key type to exercise all decrypter paths.
		// We only care about panics, not decrypt errors.
		enc.Decrypt(rsaKey)
		enc.Decrypt(ecKey)
		enc.Decrypt(aesKey)
		enc.Decrypt(string(aesKey)) // string path in newDecrypter
		enc.Decrypt(rsaJWK)        // JSONWebKey path
		enc.Decrypt(&rsaJWK)       // *JSONWebKey path
		enc.Decrypt(jwks)          // JSONWebKeySet path
		enc.Decrypt(&jwks)         // *JSONWebKeySet path
		// Try DecryptMulti with each key type
		enc.DecryptMulti(rsaKey)
		enc.DecryptMulti(ecKey)
		enc.DecryptMulti(aesKey)
		enc.DecryptMulti(string(aesKey))
	})
}

// --- Merge D: FuzzJWEConstruction (merges FuzzNewEncrypter + FuzzNewEncrypterWithCompression + FuzzNewEncrypterPBES2 + FuzzJWEDecryptWithOpaqueDecrypter) ---

// opaqueKeyDecrypterImpl wraps a real key to exercise the OpaqueKeyDecrypter path.
type opaqueKeyDecrypterImpl struct {
	key *rsa.PrivateKey
}

func (d *opaqueKeyDecrypterImpl) DecryptKey(encryptedKey []byte, header jose.Header) ([]byte, error) {
	// Use the real RSA key to decrypt
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, d.key, encryptedKey, nil)
}

func FuzzJWEConstruction(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	for i := uint8(0); i < 6; i++ {
		f.Add([]byte("test plaintext"), "password", i)
	}
	// Regression: empty plaintext triggered nil return from cipher.AEAD.Open
	for i := uint8(0); i < 6; i++ {
		f.Add([]byte(""), "password", i)
	}
	f.Fuzz(func(t *testing.T, plaintext []byte, password string, mode uint8) {
		switch mode % 6 {
		case 0:
			// Basic RSA-OAEP encrypt/decrypt round-trip (from FuzzNewEncrypter)
			encrypter, err := jose.NewEncrypter(jose.A128CBC_HS256, jose.Recipient{
				Algorithm: jose.RSA_OAEP,
				Key:       &rsaKey.PublicKey,
			}, nil)
			if err != nil {
				return
			}
			jwe, err := encrypter.Encrypt(plaintext)
			if err != nil {
				return
			}
			result, err := jwe.Decrypt(rsaKey)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}
			if string(result) != string(plaintext) {
				t.Fatalf("round-trip mismatch")
			}
		case 1:
			// AES-KW with DEFLATE compression round-trip (from FuzzNewEncrypterWithCompression)
			encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
				Algorithm: jose.A128KW,
				Key:       aesKey,
			}, &jose.EncrypterOptions{Compression: jose.DEFLATE})
			if err != nil {
				return
			}
			jwe, err := encrypter.Encrypt(plaintext)
			if err != nil {
				return
			}
			result, err := jwe.Decrypt(aesKey)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}
			if string(result) != string(plaintext) {
				t.Fatalf("compression round-trip mismatch")
			}
		case 2:
			// PBES2 with fuzzed password round-trip (from FuzzNewEncrypterPBES2)
			if len(password) == 0 {
				return
			}
			encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
				Algorithm:  jose.PBES2_HS256_A128KW,
				Key:        []byte(password),
				PBES2Count: 1000, // low for fuzz speed
			}, nil)
			if err != nil {
				return
			}
			jwe, err := encrypter.Encrypt(plaintext)
			if err != nil {
				return
			}
			result, err := jwe.Decrypt([]byte(password))
			if err != nil {
				t.Fatalf("PBES2 decrypt failed: %v", err)
			}
			if string(result) != string(plaintext) {
				t.Fatalf("PBES2 round-trip mismatch")
			}
		case 3:
			// RSA-OAEP encrypt then decrypt with opaqueKeyDecrypterImpl (from FuzzJWEDecryptWithOpaqueDecrypter)
			encrypter, err := jose.NewEncrypter(jose.A128CBC_HS256, jose.Recipient{
				Algorithm: jose.RSA_OAEP,
				Key:       &rsaKey.PublicKey,
			}, nil)
			if err != nil {
				return
			}
			jwe, err := encrypter.Encrypt(plaintext)
			if err != nil {
				return
			}
			// Decrypt with OpaqueKeyDecrypter to exercise opaque.go decryptKey
			decrypter := &opaqueKeyDecrypterImpl{key: rsaKey}
			jwe.Decrypt(decrypter)
		case 4:
			// ECDH-ES encrypt/decrypt round-trip — exercises ecDecrypterSigner.decryptKey
			encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
				Algorithm: jose.ECDH_ES,
				Key:       &ecKey.PublicKey,
			}, nil)
			if err != nil {
				return
			}
			jwe, err := encrypter.Encrypt(plaintext)
			if err != nil {
				return
			}
			result, err := jwe.Decrypt(ecKey)
			if err != nil {
				t.Fatalf("ECDH-ES decrypt failed: %v", err)
			}
			if string(result) != string(plaintext) {
				t.Fatalf("ECDH-ES round-trip mismatch")
			}
		case 5:
			// ECDH-ES+A128KW encrypt/decrypt round-trip — exercises key-unwrap path
			encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
				Algorithm: jose.ECDH_ES_A128KW,
				Key:       &ecKey.PublicKey,
			}, nil)
			if err != nil {
				return
			}
			jwe, err := encrypter.Encrypt(plaintext)
			if err != nil {
				return
			}
			result, err := jwe.Decrypt(ecKey)
			if err != nil {
				t.Fatalf("ECDH-ES+KW decrypt failed: %v", err)
			}
			if string(result) != string(plaintext) {
				t.Fatalf("ECDH-ES+KW round-trip mismatch")
			}
		}
	})
}

// FuzzNewEncrypterAllAlgorithms exercises ECDH-ES, AES-KW, AES-GCM-KW,
// DIRECT, RSA-OAEP-256, and RSA1_5 paths in asymmetric.go and symmetric.go.
func FuzzNewEncrypterAllAlgorithms(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKeyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecKeyP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	aes128Key := make([]byte, 16)
	aes192Key := make([]byte, 24)
	aes256Key := make([]byte, 32)
	rand.Read(aes128Key)
	rand.Read(aes192Key)
	rand.Read(aes256Key)

	// Seed each algorithm index
	for i := uint8(0); i < 23; i++ {
		f.Add([]byte("test plaintext"), i)
	}
	// Regression: empty plaintext triggered nil return from cipher.AEAD.Open (both GCM and CBC)
	for i := uint8(0); i < 23; i++ {
		f.Add([]byte(""), i)
	}
	f.Fuzz(func(t *testing.T, plaintext []byte, algIdx uint8) {
		type encConfig struct {
			keyAlg jose.KeyAlgorithm
			encAlg jose.ContentEncryption
			key    interface{}
			decKey interface{}
		}

		configs := []encConfig{
			// RSA variants with different content encryption
			{jose.RSA_OAEP, jose.A128GCM, &rsaKey.PublicKey, rsaKey},
			{jose.RSA_OAEP_256, jose.A256GCM, &rsaKey.PublicKey, rsaKey},
			{jose.RSA1_5, jose.A128CBC_HS256, &rsaKey.PublicKey, rsaKey},
			{jose.RSA_OAEP, jose.A192CBC_HS384, &rsaKey.PublicKey, rsaKey},
			{jose.RSA_OAEP, jose.A256CBC_HS512, &rsaKey.PublicKey, rsaKey},
			{jose.RSA_OAEP, jose.A192GCM, &rsaKey.PublicKey, rsaKey},
			// ECDH-ES with P-256, P-384, P-521 curves
			{jose.ECDH_ES, jose.A128CBC_HS256, &ecKeyP256.PublicKey, ecKeyP256},
			{jose.ECDH_ES, jose.A256GCM, &ecKeyP384.PublicKey, ecKeyP384},
			{jose.ECDH_ES_A128KW, jose.A128GCM, &ecKeyP256.PublicKey, ecKeyP256},
			{jose.ECDH_ES_A256KW, jose.A256GCM, &ecKeyP521.PublicKey, ecKeyP521},
			// Symmetric key wrapping
			{jose.A128KW, jose.A128CBC_HS256, aes128Key, aes128Key},
			{jose.A192KW, jose.A192GCM, aes192Key, aes192Key},
			{jose.A256KW, jose.A256GCM, aes256Key, aes256Key},
			{jose.A128GCMKW, jose.A128GCM, aes128Key, aes128Key},
			{jose.A256GCMKW, jose.A256GCM, aes256Key, aes256Key},
			{jose.DIRECT, jose.A128GCM, aes128Key, aes128Key},
			// PBES2 variants (low iteration count for fuzz speed)
			{jose.PBES2_HS256_A128KW, jose.A128GCM, []byte("password"), []byte("password")},
			{jose.PBES2_HS384_A192KW, jose.A192GCM, []byte("password"), []byte("password")},
			{jose.PBES2_HS512_A256KW, jose.A256GCM, []byte("password"), []byte("password")},
			// JSONWebKey recipient (exercises makeJWERecipient JSONWebKey branch)
			{jose.RSA_OAEP, jose.A128GCM, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "jwk-kid"}, rsaKey},
			// *JSONWebKey recipient
			{jose.RSA_OAEP_256, jose.A256GCM, &jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "jwk-ptr"}, rsaKey},
			// string recipient (exercises makeJWERecipient string→[]byte branch)
			{jose.A128KW, jose.A128GCM, string(aes128Key), aes128Key},
		}

		cfg := configs[int(algIdx)%len(configs)]
		rcpt := jose.Recipient{
			Algorithm: cfg.keyAlg,
			Key:       cfg.key,
		}
		// Low iteration count for PBES2 to keep fuzz fast
		switch cfg.keyAlg {
		case jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW:
			rcpt.PBES2Count = 1000
		}
		encrypter, err := jose.NewEncrypter(cfg.encAlg, rcpt, nil)
		if err != nil {
			return
		}
		_ = encrypter.Options()
		jwe, err := encrypter.Encrypt(plaintext)
		if err != nil {
			return
		}
		// Also exercise EncryptWithAuthData
		encrypter.EncryptWithAuthData(plaintext, []byte("extra-aad"))

		// Test serialization
		compact, err := jwe.CompactSerialize()
		if err != nil {
			return
		}
		_ = jwe.FullSerialize()
		_ = jwe.GetAuthData()

		// Round-trip via parse + decrypt
		parsed, err := jose.ParseEncrypted(compact, []jose.KeyAlgorithm{cfg.keyAlg}, []jose.ContentEncryption{cfg.encAlg})
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}
		result, err := parsed.Decrypt(cfg.decKey)
		if err != nil {
			t.Fatalf("failed to decrypt %s/%s: %v", cfg.keyAlg, cfg.encAlg, err)
		}
		if string(result) != string(plaintext) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

// FuzzNewEncrypterWithOptions exercises WithHeader, WithContentType, WithType
// paths in crypter.go.
func FuzzNewEncrypterWithOptions(f *testing.F) {
	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	f.Add([]byte("test"), "JWT", "custom-val")
	f.Fuzz(func(t *testing.T, plaintext []byte, typ string, customVal string) {
		opts := (&jose.EncrypterOptions{}).
			WithType(jose.ContentType(typ)).
			WithContentType(jose.ContentType(typ))
		if customVal != "" {
			opts = opts.WithHeader("x-custom", customVal)
		}
		encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
			Algorithm: jose.A128KW,
			Key:       aesKey,
		}, opts)
		if err != nil {
			return
		}
		jwe, err := encrypter.Encrypt(plaintext)
		if err != nil {
			return
		}
		jwe.Decrypt(aesKey)
	})
}

// FuzzNewMultiEncrypter exercises NewMultiEncrypter and DecryptMulti paths
// in crypter.go.
func FuzzNewMultiEncrypter(f *testing.F) {
	rsaKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	f.Add([]byte("test plaintext"), uint8(0))
	f.Add([]byte("test plaintext"), uint8(1))
	f.Add([]byte("test plaintext"), uint8(2))
	f.Fuzz(func(t *testing.T, plaintext []byte, which uint8) {
		rcpts := []jose.Recipient{
			{Algorithm: jose.RSA_OAEP, Key: &rsaKey1.PublicKey},
			{Algorithm: jose.RSA_OAEP, Key: &rsaKey2.PublicKey},
			{Algorithm: jose.A128KW, Key: aesKey},
		}
		encrypter, err := jose.NewMultiEncrypter(jose.A128CBC_HS256, rcpts,
			&jose.EncrypterOptions{Compression: jose.DEFLATE})
		if err != nil {
			return
		}
		jwe, err := encrypter.Encrypt(plaintext)
		if err != nil {
			return
		}
		full := jwe.FullSerialize()

		// Parse from full serialization (multi-recipient)
		parsed, err := jose.ParseEncrypted(full,
			[]jose.KeyAlgorithm{jose.RSA_OAEP, jose.A128KW},
			[]jose.ContentEncryption{jose.A128CBC_HS256},
		)
		if err != nil {
			t.Fatalf("failed to parse multi: %v", err)
		}

		// DecryptMulti with one of the keys
		var decKey interface{}
		switch which % 3 {
		case 0:
			decKey = rsaKey1
		case 1:
			decKey = rsaKey2
		case 2:
			decKey = aesKey
		}
		idx, _, result, err := parsed.DecryptMulti(decKey)
		if err != nil {
			t.Fatalf("DecryptMulti failed: %v", err)
		}
		if idx < 0 {
			t.Fatalf("DecryptMulti returned negative index")
		}
		if string(result) != string(plaintext) {
			t.Fatalf("multi round-trip mismatch")
		}
	})
}

// FuzzNewEncrypterInvalidCombos exercises error branches in symmetric/asymmetric
// recipient constructors by passing mismatched algorithm+key combos.
func FuzzNewEncrypterInvalidCombos(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	type combo struct {
		keyAlg jose.KeyAlgorithm
		key    interface{}
	}
	mismatches := []combo{
		{jose.A128KW, &rsaKey.PublicKey},   // AES-KW + RSA key
		{jose.RSA_OAEP, aesKey},            // RSA + symmetric key
		{jose.ECDH_ES, &rsaKey.PublicKey},  // ECDH-ES + RSA key
		{jose.RSA_OAEP, &ecKey.PublicKey},  // RSA + EC key
		{jose.A128KW, &ecKey.PublicKey},    // AES-KW + EC key
		{jose.DIRECT, &rsaKey.PublicKey},   // DIRECT + RSA key
		{jose.A128GCMKW, &rsaKey.PublicKey}, // AES-GCM-KW + RSA key
	}

	for i := range mismatches {
		f.Add(uint8(i))
	}
	f.Fuzz(func(t *testing.T, idx uint8) {
		m := mismatches[int(idx)%len(mismatches)]
		jose.NewEncrypter(jose.A128GCM, jose.Recipient{
			Algorithm: m.keyAlg,
			Key:       m.key,
		}, nil)
	})
}
