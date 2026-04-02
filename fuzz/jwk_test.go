package fuzz

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// FuzzJWKRoundTrip consolidates unmarshal, marshal, thumbprint, IsPublic,
// Public, Valid, and marshal-unmarshal round-trip into a single fuzz target.
func FuzzJWKRoundTrip(f *testing.F) {
	// Public keys
	f.Add([]byte(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`))
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`))
	f.Add([]byte(`{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"kty":"unknown"}`))
	f.Add([]byte(``))

	// Malformed key seeds to exercise error paths
	f.Add([]byte(`{"kty":"RSA","n":"AA"}`))                                  // RSA missing e
	f.Add([]byte(`{"kty":"RSA","e":"AQAB"}`))                                // RSA missing n
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"AA"}`))                     // EC missing y
	f.Add([]byte(`{"kty":"EC","crv":"P-256","y":"AA"}`))                     // EC missing x
	f.Add([]byte(`{"kty":"EC","crv":"P-999","x":"AA","y":"AA"}`))            // EC unknown curve
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519"}`))                           // Ed25519 missing x
	f.Add([]byte(`{"kty":"EC","crv":"P-256"}`))                              // EC key missing x/y
	f.Add([]byte(`{"kty":"RSA"}`))                                           // RSA key missing n/e
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AA"}`))                  // short Ed25519
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":""}`)) // EC private with missing d
	f.Add([]byte(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"AA"}`)) // RSA private with wrong primes
	// Regression: empty OCT key caused marshal/unmarshal round-trip failure
	f.Add([]byte(`{"kty":"oct","k":""}`))
	// Regression: empty RSA n/e caused marshal to drop fields, then re-unmarshal failed
	f.Add([]byte(`{"kty":"RSA","n":"","e":""}`))
	// Regression: RSA e decoding to zero caused nil deref in rsaThumbprintInput via newBufferFromInt(0)
	f.Add([]byte(`{"kty":"RSA","n":"00","e":"AA"}`))
	// Regression c02d7be: unsupported OKP curve error message had missing quote
	f.Add([]byte(`{"kty":"OKP","crv":"X25519","x":"AA"}`))

	// Generate key types and seed with their JSON (both public and private)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKeyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecKeyP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	hmacKey := make([]byte, 32)
	rand.Read(hmacKey)

	// Public keys (including P-384, P-521 for curveName/curveSize/ecPublicKey coverage)
	for _, key := range []interface{}{&rsaKey.PublicKey, &ecKeyP256.PublicKey, &ecKeyP384.PublicKey, &ecKeyP521.PublicKey, edPub} {
		b, _ := (&jose.JSONWebKey{Key: key}).MarshalJSON()
		if b != nil {
			f.Add(b)
		}
	}
	// Private keys — exercises fromRsaPrivateKey, fromEcPrivateKey, fromEdPrivateKey, fromSymmetricKey
	for _, key := range []interface{}{rsaKey, ecKeyP256, ecKeyP384, ecKeyP521, edPriv, hmacKey} {
		b, _ := (&jose.JSONWebKey{Key: key}).MarshalJSON()
		if b != nil {
			f.Add(b)
		}
	}
	// JWK with x5c certificate chain — exercises Certificates field in MarshalJSON/UnmarshalJSON
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz-jwk-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, certErr := x509.CreateCertificate(rand.Reader, template, template, &ecKeyP256.PublicKey, ecKeyP256)
	if certErr == nil {
		cert, _ := x509.ParseCertificate(certDER)
		if cert != nil {
			jwkWithCert := jose.JSONWebKey{
				Key:          &ecKeyP256.PublicKey,
				Certificates: []*x509.Certificate{cert},
			}
			b, _ := jwkWithCert.MarshalJSON()
			if b != nil {
				f.Add(b)
			}
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON(data)
		if err != nil {
			return
		}
		key.IsPublic()
		key.Public()
		key.Valid()
		key.Thumbprint(crypto.SHA256)

		marshaled, err := key.MarshalJSON()
		if err != nil {
			return
		}
		var key2 jose.JSONWebKey
		if err := key2.UnmarshalJSON(marshaled); err != nil {
			t.Fatalf("failed to re-unmarshal: %v", err)
		}
	})
}

// FuzzJWKValidDirect exercises Valid() with directly-constructed invalid keys
// that bypass the UnmarshalJSON validation.
func FuzzJWKValidDirect(f *testing.F) {
	f.Add(uint8(0))
	f.Add(uint8(1))
	f.Add(uint8(2))
	f.Add(uint8(3))
	f.Add(uint8(4))
	f.Add(uint8(5))
	f.Add(uint8(6))
	f.Add(uint8(7))
	f.Add(uint8(8))
	f.Add(uint8(9))
	f.Fuzz(func(t *testing.T, idx uint8) {
		var jwk jose.JSONWebKey
		switch idx % 10 {
		case 0:
			jwk.Key = nil // nil key
		case 1:
			jwk.Key = &ecdsa.PublicKey{} // EC with nil Curve/X/Y
		case 2:
			jwk.Key = &ecdsa.PrivateKey{} // EC private with nil everything
		case 3:
			jwk.Key = &rsa.PublicKey{} // RSA with nil N, E=0
		case 4:
			jwk.Key = &rsa.PrivateKey{} // RSA private with nil everything
		case 5:
			jwk.Key = ed25519.PublicKey([]byte{1, 2, 3}) // wrong size
		case 6:
			jwk.Key = ed25519.PrivateKey([]byte{1, 2, 3}) // wrong size
		case 7:
			jwk.Key = "unsupported type" // unknown type
		case 8:
			jwk.Key = &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: nil, E: 0}} // RSA private zero
		case 9:
			jwk.Key = ed25519.PublicKey(make([]byte, 32)) // valid size
		}
		jwk.Valid()
	})
}

func FuzzJWKSetKey(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"EC","kid":"mykey","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`), "mykey")
	f.Add([]byte(`{"keys":[]}`), "missing")
	f.Fuzz(func(t *testing.T, data []byte, kid string) {
		var keySet jose.JSONWebKeySet
		if err := json.Unmarshal(data, &keySet); err != nil {
			return
		}
		keySet.Key(kid)
	})
}

// FuzzHeaderCertificates exercises JWS header certificate parsing and
// the Certificates() verification path.
func FuzzHeaderCertificates(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature")

	// Create a self-signed certificate and a JWS with x5c header to exercise
	// the Certificates() path (shared.go:209) which requires parsed certs.
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if certKey != nil {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "fuzz-test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
		if err == nil {
			certB64 := base64.StdEncoding.EncodeToString(certDER)
			// Build a JWS with x5c header: {"alg":"ES256","x5c":["<cert>"]}
			signer, err := jose.NewSigner(
				jose.SigningKey{Algorithm: jose.ES256, Key: certKey},
				&jose.SignerOptions{
					ExtraHeaders: map[jose.HeaderKey]interface{}{
						"x5c": []string{certB64},
					},
				},
			)
			if err == nil {
				if sig, err := signer.Sign([]byte("test")); err == nil {
					if s, err := sig.CompactSerialize(); err == nil {
						f.Add(s)
					}
				}
			}
		}
	}

	f.Fuzz(func(t *testing.T, data string) {
		sig, err := jose.ParseSigned(data, allSignatureAlgorithms)
		if err != nil {
			return
		}
		for _, s := range sig.Signatures {
			s.Header.Certificates(x509.VerifyOptions{})
		}
	})
}
