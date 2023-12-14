/*-
 * Copyright 2016 Zbigniew Mandziejewicz
 * Copyright 2016 Square, Inc.
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

package jwt

import (
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
)

var (
	hmacSignedToken                string
	rsaSignedToken                 = `eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJzY29wZXMiOlsiczEiLCJzMiJdLCJzdWIiOiJzdWJqZWN0In0.UDDtyK9gC9kyHltcP7E_XODsnqcJWZIiXeGmSAH7SE9YKy3N0KSfFIN85dCNjTfs6zvy4rkrCHzLB7uKAtzMearh3q7jL4nxbhUMhlUcs_9QDVoN4q_j58XmRqBqRnBk-RmDu9TgcV8RbErP4awpIhwWb5UU-hR__4_iNbHdKqwSUPDKYGlf5eicuiYrPxH8mxivk4LRD-vyRdBZZKBt0XIDnEU4TdcNCzAXojkftqcFWYsczwS8R4JHd1qYsMyiaWl4trdHZkO4QkeLe34z4ZAaPMt3wE-gcU-VoqYTGxz-K3Le2VaZ0r3j_z6bOInsv0yngC_cD1dCXMyQJWnWjQ`
	rsaSignedTokenWithKid          = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImZvb2JhciJ9.eyJpc3MiOiJpc3N1ZXIiLCJzY29wZXMiOlsiczEiLCJzMiJdLCJzdWIiOiJzdWJqZWN0In0.RxZhTRfPDb6UJ58FwvC89GgJGC8lAO04tz5iLlBpIJsyPZB0X_UgXSj0SGVFm2jbP_i-ZVH4HFC2fMB1n-so9CnCOpunWwhYNdgF6ewQJ0ADTWwfDGsK12UOmyT2naaZN8ZUBF8cgPtOgdWqQjk2Ng9QFRJxlUuKYczBp7vjWvgX8WMwQcaA-eK7HtguR4e9c4FMbeFK8Soc4jCsVTjIKdSn9SErc42gFu65NI1hZ3OPe_T7AZqdDjCkJpoiJ65GdD_qvGkVndJSEcMp3riXQpAy0JbctVkYecdFaGidbxHRrdcQYHtKn-XGMCh2uoBKleUr1fTMiyCGPQQesy3xHw`
	invalidPayloadSignedToken      = `eyJhbGciOiJIUzI1NiJ9.aW52YWxpZC1wYXlsb2Fk.ScBKKm18jcaMLGYDNRUqB5gVMRZl4DM6dh3ShcxeNgY`
	invalidPartsSignedToken        = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwic2NvcGVzIjpbInMxIiwiczIiXX0`
	hmacEncryptedToken             = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..NZrU98U4QNO0y-u6.HSq5CvlmkUT1BPqLGZ4.1-zuiZ4RbHrTTUoA8Dvfhg`
	rsaEncryptedToken              = `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.IvkVHHiI8JwwavvTR80xGjYvkzubMrZ-TDDx8k8SNJMEylfFfNUc7F2rC3WAABF_xmJ3SW2A6on-S6EAG97k0RsjqHHNqZuaFpDvjeuLqZFfYKzI45aCtkGG4C2ij2GbeySqJ784CcvFJPUWJ-6VPN2Ho2nhefUSqig0jE2IvOKy1ywTj_VBVBxF_dyXFnXwxPKGUQr3apxrWeRJfDh2Cf8YPBlLiRznjfBfwgePB1jP7WCZNwItj10L7hsT_YWEx01XJcbxHaXFLwKyVzwWaDhreFyaWMRbGqEfqVuOT34zfmhLDhQlgLLwkXrvYqX90NsQ9Ftg0LLIfRMbsfdgug.BFy2Tj1RZN8yq2Lk-kMiZQ.9Z0eOyPiv5cEzmXh64RlAQ36Uvz0WpZgqRcc2_69zHTmUOv0Vnl1I6ks8sTraUEvukAilolNBjBj47s0b4b-Og.VM8-eJg5ZsqnTqs0LtGX_Q`
	invalidPayloadEncryptedToken   = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..T4jCS4Yyw1GCH0aW.y4gFaMITdBs_QZM8RKrL.6MPyk1cMVaOJFoNGlEuaRQ`
	invalidPartsEncryptedToken     = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..NZrU98U4QNO0y-u6.HSq5CvlmkUT1BPqLGZ4`
	signedAndEncryptedToken        = `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0.icnR7M1HSgMDaUnJhfzT5nLmT0eRPeNsKPkioNcyq9TZsm-LgbE7wZkNFGfQqYwvbmrZ3UpOhNkrq4n2KN3N1dtjH9TVxzfMxz2OMh0dRWUNMi58EMadhmIpH3PLyyaeDyd0dyHpOIRPFTAoOdn2GoO_flV5CvPMhgdVKYB3h3vQW-ZZDu4cOZwXAjTuThdoUZCNWFhJhXyj-PrKLyVpX6rE1o4X05IS8008SLZyx-PZlsUPyLs6CJi7Z4PzZRzOJTV00a-7UOi-fBKBZV5V8eRpWuzJ673pMALlRCBzrRin-JeEA_QnAejtMAHG7RSGP60easQN4I-0jLTQNNNynw.oFrO-5ZgRrnWmbkPsbyMiQ.BVaWUzlrdfhe0otPJpb3DGoDCT6-BOmN_Pgq5NOqVFYIAwG5pM4pf7TaiPUJeQLf0phbLgpT4RfJ20Zhwfc2MH5unCqc8TZEP2dOrYRhb8o-X57x6IQppIDbjK2i_CAWf3yF5JUB7qRqOizpKZTh3HFTVEglY3WF8tAJ8KpnatTUmwcnqlyjdBFvYu4usiyvc_u9wNbXx5-lFt0slQYleHQMUirBprKyswIBjMoFJEe7kDvU_MCKI4NI9_fSfWJpaUdNxQEvRYR1PV4ZQdwBY0X9u2n2QH5iVQMrmgmQ5hPbWxwRv1-7jXBMPBpGeFQZHeEtSwif1_Umwyt8cDyRChb3OM7XQ3eY0UJRrbmvhcLWIcMp8FpblDaBinbjD6qIVXZVmaAdIbi2a_HblfoeL3-UABb82AAxOqQcAFjDEDTR2TFalDXSwgPZrAaQ_Mql3eFe9r2y0UVkgG7XYF4ik8sSK48CkZPUvkZFr-K9QMq-RZLzT3Zw0edxNaKgje27S26H9qClh6CCr9nk38AZZ76_Xz7f-Fil5xI0Dq95UzvwW__U3JJWE6OVUVx_RVJgdOJn8_B7hluckwBLUblscA.83pPXNnH0sKgHvFboiJVDA`
	invalidSignedAndEncryptedToken = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIn0K..PmqSKNuL84466r0zAFCy6A.sSN_7NJs4l7FAj6HcBzdYjV3FGu1MsqZCk_zNjpp6qsYynR3pJWU3jLUVYrRkeQKOaJAmDwOHHdrq9tBPh4-GD3zgtM1Fm5mJ2oVrbQUr2nllYWIsdb2LhVR9pxdhjDm6wlpJxcIuY1PkeMIVUupXEBEemk9atiJWAjoGqXVPO_pI6-egGseqYo1PjUXY7Cnz6SBq0W3yNk3Edf_xA-lLZuiALuatsweNJUbTwqTzhOHQ6aPAiPafc7jQGvp9YXYi6X5oQ85cXPTCnGQWS7LMHPME5gRzb4_Cz7M1QhZGdbOS8bLnxKMRZwbhvdc9-JhTqi8JbA0mp0OnWr77iPBCeFAUVEbqxTMeWOwLCQ6RjoTtx3vXnVfgqKSrkdMKGhC33tEfxy_Wg5WEm_3jeITSCvQJtwItNVhhlOrcqPD71JMLhneAnRtSqys5TbporUOpwi43DStCYBdrueE-M0dlo3C6tO0KDgAgg48JaiW_76AcO32vJTKKl9rZ0ybku58lqHJtMNR4bJ7PjTv3hPhfA.p4VEoJ3y7THiJwRpXBlsHQ`
)

type customClaims struct {
	Scopes []string `json:"scopes,omitempty"`
}

func init() {
	var err error
	hmacSignedToken, err = Signed(hmacSigner).Claims(Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}).Claims(customClaims{
		Scopes: []string{"s1", "s2"},
	}).Serialize()
	if err != nil {
		panic(err)
	}
}

func TestGetClaimsWithoutVerification(t *testing.T) {
	tok, err := ParseSigned(hmacSignedToken, []jose.SignatureAlgorithm{jose.HS256})
	if assert.NoError(t, err, "Error parsing signed token.") {
		c := &Claims{}
		c2 := &customClaims{}

		err := tok.UnsafeClaimsWithoutVerification(c, c2)
		if err != nil {
			t.Errorf("Error not expected: %s", err)
		}
		assert.Equal(t, "subject", c.Subject)
		assert.Equal(t, "issuer", c.Issuer)
		assert.Equal(t, []string{"s1", "s2"}, c2.Scopes)

	}
	tok, err = ParseEncrypted(hmacEncryptedToken, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128GCM})
	if assert.NoError(t, err, "Error parsing encrypted token.") {
		c := Claims{}
		err := tok.UnsafeClaimsWithoutVerification(c)
		if err == nil {
			t.Errorf("Error expected")
		}
	}
}

func TestDecodeTokenWithJWKS(t *testing.T) {
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "foobar",
				Key:   &testPrivRSAKey1.PublicKey,
			},
		},
	}

	tok, err := ParseSigned(rsaSignedTokenWithKid, []jose.SignatureAlgorithm{jose.RS256})
	if assert.NoError(t, err, "Error parsing signed token.") {
		cl := make(map[string]interface{})
		expected := map[string]interface{}{
			"sub":    "subject",
			"iss":    "issuer",
			"scopes": []interface{}{"s1", "s2"},
		}

		if assert.NoError(t, tok.Claims(jwks, &cl)) {
			assert.Equal(t, expected, cl)
		}

		cl = make(map[string]interface{})
		if assert.NoError(t, tok.Claims(*jwks, &cl)) {
			assert.Equal(t, expected, cl)
		}
	}
}

func TestDecodeToken(t *testing.T) {
	tok, err := ParseSigned(hmacSignedToken, []jose.SignatureAlgorithm{jose.HS256})
	if assert.NoError(t, err, "Error parsing signed token.") {
		c := &Claims{}
		c2 := &customClaims{}
		if assert.NoError(t, tok.Claims(sharedKey, c, c2)) {
			assert.Equal(t, "subject", c.Subject)
			assert.Equal(t, "issuer", c.Issuer)
			assert.Equal(t, []string{"s1", "s2"}, c2.Scopes)
		}
	}
	assert.EqualError(t, tok.Claims([]byte("invalid-secret")), "go-jose/go-jose: error in cryptographic primitive")

	tok2, err := ParseSigned(rsaSignedToken, []jose.SignatureAlgorithm{jose.RS256})
	if assert.NoError(t, err, "Error parsing encrypted token.") {
		c := make(map[string]interface{})
		if assert.NoError(t, tok2.Claims(&testPrivRSAKey1.PublicKey, &c)) {
			assert.Equal(t, map[string]interface{}{
				"sub":    "subject",
				"iss":    "issuer",
				"scopes": []interface{}{"s1", "s2"},
			}, c)
		}
	}
	assert.EqualError(t, tok.Claims(&testPrivRSAKey2.PublicKey), "go-jose/go-jose: error in cryptographic primitive")

	tok3, err := ParseSigned(invalidPayloadSignedToken, []jose.SignatureAlgorithm{jose.HS256})
	if assert.NoError(t, err, "Error parsing signed token.") {
		assert.Error(t, tok3.Claims(sharedKey, &Claims{}), "Expected unmarshaling claims to fail.")
	}

	_, err = ParseSigned(invalidPartsSignedToken, []jose.SignatureAlgorithm{jose.HS256})
	assert.EqualError(t, err, "go-jose/go-jose: compact JWS format must have three parts")

	tok4, err := ParseEncrypted(hmacEncryptedToken, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128GCM})
	if assert.NoError(t, err, "Error parsing encrypted token.") {
		c := Claims{}
		if assert.NoError(t, tok4.Claims(sharedEncryptionKey, &c)) {
			assert.Equal(t, "foo", c.Subject)
		}
	}
	assert.EqualError(t, tok4.Claims([]byte("invalid-secret-key")), "go-jose/go-jose: error in cryptographic primitive")

	_, err = ParseEncrypted(rsaEncryptedToken, []jose.KeyAlgorithm{jose.RSA1_5}, []jose.ContentEncryption{jose.A128CBC_HS256})
	assert.Error(t, err, "Expected error trying to parse token with symmetric encryption algorithm")

	tok6, err := ParseEncrypted(invalidPayloadEncryptedToken, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128GCM})
	if assert.NoError(t, err, "Error parsing encrypted token.") {
		assert.Error(t, tok6.Claims(sharedEncryptionKey, &Claims{}))
	}

	_, err = ParseEncrypted(invalidPartsEncryptedToken, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128GCM})
	assert.EqualError(t, err, "go-jose/go-jose: compact JWE format must have five parts")

	_, err = ParseSignedAndEncrypted(signedAndEncryptedToken,
		[]jose.KeyAlgorithm{jose.RSA1_5},
		[]jose.ContentEncryption{jose.A128CBC_HS256},
		[]jose.SignatureAlgorithm{jose.RS256},
	)
	assert.Error(t, err, "Expected error trying to parse signed-then-encrypted token with symmetric encryption algorithm")

	_, err = ParseSignedAndEncrypted(invalidSignedAndEncryptedToken,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A128CBC_HS256},
		[]jose.SignatureAlgorithm{jose.RS256})
	assert.EqualError(t, err, "go-jose/go-jose/jwt: expected content type to be JWT (cty header)")
}

func TestTamperedJWT(t *testing.T) {
	key := []byte("1234567890123456")

	sig, _ := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		(&jose.EncrypterOptions{}).WithType("JWT"))

	cl := Claims{
		Subject: "foo",
		Issuer:  "bar",
	}

	raw, _ := Encrypted(sig).Claims(cl).Serialize()

	// Modify with valid base64 junk
	r := strings.Split(raw, ".")
	r[2] = "b3RoZXJ0aGluZw"
	raw = strings.Join(r, ".")

	tok, _ := ParseEncrypted(raw, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128GCM})

	cl = Claims{}
	err := tok.Claims(key, &cl)
	if err == nil {
		t.Error("Claims() on invalid token should fail")
	}
}

func BenchmarkDecodeSignedToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ParseSigned(hmacSignedToken, []jose.SignatureAlgorithm{jose.HS256}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeEncryptedHMACToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ParseEncrypted(hmacEncryptedToken, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128GCM}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestValidateKeyEncryptionAlgorithm(t *testing.T) {
	for _, alg := range []jose.KeyAlgorithm{
		jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256,
		jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
	} {
		err := validateKeyEncryptionAlgorithm([]jose.KeyAlgorithm{alg})
		if err == nil {
			t.Errorf("expected error for %s, got none", alg)
		}
		if !strings.Contains(err.Error(), "asymmetric encryption algorithms not supported") {
			t.Errorf("got wrong error for %s: %s", alg, err)
		}
	}
	for _, alg := range []jose.KeyAlgorithm{
		jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW,
	} {
		err := validateKeyEncryptionAlgorithm([]jose.KeyAlgorithm{alg})
		if err == nil {
			t.Errorf("expected error for %s, got none", alg)
		}
		if !strings.Contains(err.Error(), "password-based encryption not supported") {
			t.Errorf("got wrong error for %s: %s", alg, err)
		}
	}

	for _, alg := range []jose.KeyAlgorithm{
		jose.A128KW, jose.A192KW, jose.A256KW,
		jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
		jose.DIRECT,
		jose.KeyAlgorithm("XYZ"),
	} {
		err := validateKeyEncryptionAlgorithm([]jose.KeyAlgorithm{alg})
		if err != nil {
			t.Errorf("expected success for %s, got %s", alg, err)
		}
	}
}
