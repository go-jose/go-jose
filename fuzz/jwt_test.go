package fuzz

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// jwtSymmetricKeyAlgorithms are algorithms allowed by jwt.ParseEncrypted
// (excludes asymmetric and PBES2).
var jwtSymmetricKeyAlgorithms = []jose.KeyAlgorithm{
	jose.A128KW, jose.A192KW, jose.A256KW,
	jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
	jose.DIRECT,
}

// FuzzJWTParse merges FuzzJWTParseSigned, FuzzJWTParseEncrypted,
// and FuzzJWTParseSignedAndEncrypted.
func FuzzJWTParse(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	f.Add("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a.b.c.d")
	f.Add("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0.a.b.c.d")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		jwt.ParseSigned(data, allSignatureAlgorithms)
		jwt.ParseEncrypted(data, jwtSymmetricKeyAlgorithms, allContentEncryption)
		jwt.ParseSignedAndEncrypted(data, jwtSymmetricKeyAlgorithms, allContentEncryption, allSignatureAlgorithms)
	})
}

// FuzzJWTClaimsUnsafe merges FuzzJWTClaims, FuzzJWTUnsafeClaimsWithoutVerification,
// FuzzNestedJWTDecrypt, and FuzzJWTParseEncryptedWithValidToken.
func FuzzJWTClaimsUnsafe(f *testing.F) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	// Create a valid signed JWT as seed
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: edKey}, nil)
	if signer != nil {
		builder := jwt.Signed(signer).Claims(jwt.Claims{
			Subject: "test",
			Issuer:  "fuzz",
		})
		token, _ := builder.Serialize()
		if token != "" {
			f.Add(token)
		}
	}

	// Create a valid encrypted JWT as seed
	enc, _ := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
		Algorithm: jose.A128KW,
		Key:       aesKey,
	}, nil)
	if enc != nil {
		token, _ := jwt.Encrypted(enc).Claims(jwt.Claims{
			Subject: "test",
			Issuer:  "fuzz",
		}).Serialize()
		if token != "" {
			f.Add(token)
		}
	}

	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaXNzIjoiZnV6eiJ9.sig")
	f.Add("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0.a.b.c.d")
	f.Add("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a.b.c.d")
	f.Fuzz(func(t *testing.T, data string) {
		// Parse signed JWT and call UnsafeClaimsWithoutVerification
		tok, err := jwt.ParseSigned(data, allSignatureAlgorithms)
		if err == nil {
			var claims jwt.Claims
			tok.UnsafeClaimsWithoutVerification(&claims)

			var claims2 jwt.Claims
			var extra map[string]interface{}
			tok.UnsafeClaimsWithoutVerification(&claims2, &extra)
		}

		// Parse encrypted JWT and call Claims with aesKey
		etok, err := jwt.ParseEncrypted(data, jwtSymmetricKeyAlgorithms, allContentEncryption)
		if err == nil {
			var claims jwt.Claims
			etok.Claims(aesKey, &claims)
		}

		// Parse signed-and-encrypted JWT and try to decrypt
		nested, err := jwt.ParseSignedAndEncrypted(data,
			[]jose.KeyAlgorithm{jose.A128KW, jose.A192KW, jose.A256KW, jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256, jose.DIRECT},
			allContentEncryption,
			allSignatureAlgorithms,
		)
		if err == nil {
			nested.Decrypt(rsaKey)
		}
	})
}

// FuzzJWTTypes merges FuzzNumericDateUnmarshalJSON, FuzzAudienceUnmarshalJSON,
// FuzzNumericDateMarshalJSON, FuzzAudienceMarshalJSON, and FuzzAudienceContains.
func FuzzJWTTypes(f *testing.F) {
	f.Add([]byte("1516239022"), "single", "target", int64(1516239022))
	f.Add([]byte("1516239022.5"), "a", "b", int64(0))
	f.Add([]byte("0"), "", "", int64(-1))
	f.Add([]byte("-1"), "target", "target", int64(999999999999))
	f.Add([]byte("999999999999"), "single", "", int64(1516239022))
	f.Add([]byte(""), "", "", int64(0))
	f.Add([]byte("null"), "a", "b", int64(0))
	f.Add([]byte(`"not a number"`), "", "", int64(0))
	f.Add([]byte(`"single"`), "a", "b", int64(0))
	f.Add([]byte(`["a","b","c"]`), "", "", int64(0))
	f.Add([]byte(`[]`), "", "", int64(0))
	f.Add([]byte(`123`), "", "", int64(0))
	f.Fuzz(func(t *testing.T, data []byte, strA string, strB string, val int64) {
		// NumericDate UnmarshalJSON
		var n jwt.NumericDate
		n.UnmarshalJSON(data)

		// Audience UnmarshalJSON
		var aud jwt.Audience
		aud.UnmarshalJSON(data)

		// NumericDate MarshalJSON, Time, NewNumericDate
		nd := jwt.NumericDate(val)
		nd.MarshalJSON()
		nd.Time()
		var nilND *jwt.NumericDate
		nilND.Time()
		jwt.NewNumericDate(time.Time{})
		jwt.NewNumericDate(time.Unix(val, 0))

		// Audience MarshalJSON
		aud1 := jwt.Audience{strA}
		aud1.MarshalJSON()
		if strB != "" {
			aud2 := jwt.Audience{strA, strB}
			aud2.MarshalJSON()
		}
		aud3 := jwt.Audience{}
		aud3.MarshalJSON()

		// Audience Contains
		jwt.Audience{strA}.Contains(strB)
	})
}

// FuzzClaimsValidation merges FuzzClaimsValidate and FuzzClaimsValidateWithLeeway.
func FuzzClaimsValidation(f *testing.F) {
	f.Add("issuer", "subject", "audience", "id", int64(1516239022), int64(1516239022), int64(1516239022), int64(1516239022), int64(60))
	f.Add("", "", "", "", int64(0), int64(0), int64(0), int64(0), int64(0))
	f.Add("iss", "sub", "aud", "id1", int64(1000), int64(500), int64(2000), int64(500), int64(0))
	f.Add("iss", "sub", "aud", "id2", int64(3000), int64(2000), int64(1000), int64(500), int64(0))
	f.Add("iss", "sub", "aud", "id3", int64(3000), int64(500), int64(1000), int64(2000), int64(0))
	f.Fuzz(func(t *testing.T, iss, sub, aud, id string, exp, nbf, now, iat, leewaySeconds int64) {
		// Bound the leeway to avoid huge durations
		if leewaySeconds < 0 {
			leewaySeconds = -leewaySeconds
		}
		if leewaySeconds > 3600 {
			leewaySeconds = 3600
		}

		expDate := jwt.NumericDate(exp)
		nbfDate := jwt.NumericDate(nbf)
		iatDate := jwt.NumericDate(iat)
		claims := jwt.Claims{
			Issuer:    iss,
			Subject:   sub,
			Audience:  jwt.Audience{aud},
			ID:        id,
			Expiry:    &expDate,
			NotBefore: &nbfDate,
			IssuedAt:  &iatDate,
		}
		// Exercise WithTime (jwt/validation.go:46)
		expected := jwt.Expected{
			Issuer:      iss,
			Subject:     sub,
			AnyAudience: jwt.Audience{aud},
			ID:          id,
		}.WithTime(time.Unix(now, 0))

		// Exercise Validate
		claims.Validate(expected)

		// Exercise ValidateWithLeeway
		claims.ValidateWithLeeway(expected, time.Duration(leewaySeconds)*time.Second)

		// Mismatched issuer/subject/audience/id to hit error paths
		claims.ValidateWithLeeway(jwt.Expected{
			Issuer:      iss + "-wrong",
			Subject:     sub + "-wrong",
			AnyAudience: jwt.Audience{aud + "-wrong"},
			ID:          id + "-wrong",
			Time:        time.Unix(now, 0),
		}, time.Duration(leewaySeconds)*time.Second)

		// Zero time (uses time.Now()) path
		claims.ValidateWithLeeway(jwt.Expected{}, 0)
	})
}

// FuzzJWTBuilder merges FuzzJWTSignedBuilderRoundTrip, FuzzJWTEncryptedBuilderRoundTrip,
// FuzzJWTSignedAndEncryptedBuilderRoundTrip, FuzzJWTSignedBuilderToken,
// FuzzJWTEncryptedBuilderToken, and FuzzJWTNestedBuilderTokenAndFullSerialize.
func FuzzJWTBuilder(f *testing.F) {
	hmacKey := make([]byte, 64)
	aesKey := make([]byte, 16)
	rand.Read(hmacKey)
	rand.Read(aesKey)

	f.Add("issuer", "subject", "audience", uint8(0))
	f.Add("issuer", "subject", "audience", uint8(1))
	f.Add("issuer", "subject", "audience", uint8(2))
	f.Add("issuer", "subject", "audience", uint8(3))
	f.Add("issuer", "subject", "audience", uint8(4))
	f.Add("issuer", "subject", "audience", uint8(5))
	f.Fuzz(func(t *testing.T, iss, sub, aud string, mode uint8) {
		if !utf8.ValidString(iss) || !utf8.ValidString(sub) || !utf8.ValidString(aud) {
			t.Skip("invalid UTF-8")
		}

		switch mode % 6 {
		case 0:
			// Signed builder round-trip
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey}, nil)
			if err != nil {
				return
			}
			builder := jwt.Signed(signer).
				Claims(jwt.Claims{
					Issuer:  iss,
					Subject: sub,
				}).
				Claims(map[string]interface{}{
					"aud":    aud,
					"custom": "value",
				})
			token, err := builder.Serialize()
			if err != nil {
				return
			}
			parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.HS256})
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}
			var claims jwt.Claims
			if err := parsed.Claims(hmacKey, &claims); err != nil {
				t.Fatalf("failed to verify claims: %v", err)
			}
			if claims.Issuer != iss || claims.Subject != sub {
				t.Fatalf("round-trip mismatch")
			}

		case 1:
			// Encrypted builder round-trip
			enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
				Algorithm: jose.A128KW,
				Key:       aesKey,
			}, nil)
			if err != nil {
				return
			}
			token, err := jwt.Encrypted(enc).Claims(jwt.Claims{
				Issuer:   iss,
				Subject:  sub,
				Audience: jwt.Audience{aud},
			}).Serialize()
			if err != nil {
				return
			}
			parsed, err := jwt.ParseEncrypted(token, jwtSymmetricKeyAlgorithms, allContentEncryption)
			if err != nil {
				t.Fatalf("failed to parse encrypted JWT: %v", err)
			}
			var claims jwt.Claims
			if err := parsed.Claims(aesKey, &claims); err != nil {
				t.Fatalf("failed to decrypt claims: %v", err)
			}
			if claims.Issuer != iss || claims.Subject != sub {
				t.Fatalf("encrypted JWT round-trip mismatch")
			}

		case 2:
			// Signed-and-encrypted builder round-trip
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey}, nil)
			if err != nil {
				return
			}
			enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
				Algorithm: jose.A128KW,
				Key:       aesKey,
			}, (&jose.EncrypterOptions{}).WithContentType("JWT"))
			if err != nil {
				return
			}
			token, err := jwt.SignedAndEncrypted(signer, enc).Claims(jwt.Claims{
				Issuer:   iss,
				Subject:  sub,
				Audience: jwt.Audience{aud},
			}).Serialize()
			if err != nil {
				return
			}
			nested, err := jwt.ParseSignedAndEncrypted(token, jwtSymmetricKeyAlgorithms, allContentEncryption, allSignatureAlgorithms)
			if err != nil {
				t.Fatalf("failed to parse nested JWT: %v", err)
			}
			inner, err := nested.Decrypt(aesKey)
			if err != nil {
				t.Fatalf("failed to decrypt nested JWT: %v", err)
			}
			var claims jwt.Claims
			if err := inner.Claims(hmacKey, &claims); err != nil {
				t.Fatalf("failed to verify inner claims: %v", err)
			}
			if claims.Issuer != iss || claims.Subject != sub {
				t.Fatalf("nested JWT round-trip mismatch")
			}

		case 3:
			// Signed builder Token()
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey}, nil)
			if err != nil {
				return
			}
			tok, err := jwt.Signed(signer).Claims(jwt.Claims{
				Issuer:  iss,
				Subject: sub,
			}).Token()
			if err != nil {
				return
			}
			var claims jwt.Claims
			tok.Claims(hmacKey, &claims)

		case 4:
			// Encrypted builder Token()
			enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
				Algorithm: jose.A128KW,
				Key:       aesKey,
			}, nil)
			if err != nil {
				return
			}
			tok, err := jwt.Encrypted(enc).Claims(jwt.Claims{
				Issuer:  iss,
				Subject: sub,
			}).Token()
			if err != nil {
				return
			}
			var claims jwt.Claims
			tok.Claims(aesKey, &claims)

		case 5:
			// Nested builder Token() and Serialize
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey}, nil)
			if err != nil {
				return
			}
			enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{
				Algorithm: jose.A128KW,
				Key:       aesKey,
			}, (&jose.EncrypterOptions{}).WithContentType("JWT"))
			if err != nil {
				return
			}
			nb := jwt.SignedAndEncrypted(signer, enc).Claims(jwt.Claims{
				Issuer:  iss,
				Subject: sub,
			})
			nb.Serialize()
			nb.Token()
		}
	})
}
