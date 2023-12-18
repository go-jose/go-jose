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

package jwt_test

import (
	"fmt"
	"strings"
	"time"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var sharedKey = []byte("0102030405060708090A0B0C0D0E0F10")
var sharedEncryptionKey = []byte("itsa16bytesecret")
var signer, _ = jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: sharedKey}, &jose.SignerOptions{})

func ExampleParseSigned() {
	raw := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.OFD0iVfPczqWBA_TRi1jGB5PF699eekcHt4D6qNoimc`

	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		fmt.Printf("parsing JWT: %s\n", err)
		return
	}

	out := jwt.Claims{}
	if err := tok.Claims(sharedKey, &out); err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}
	fmt.Printf("iss: %s, sub: %s\n", out.Issuer, out.Subject)
	// Output: iss: issuer, sub: subject
}

func ExampleParseEncrypted() {
	key := []byte("itsa16bytesecret")
	raw := `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..jg45D9nmr6-8awml.z-zglLlEw9MVkYHi-Znd9bSwc-oRGbqKzf9WjXqZxno.kqji2DiZHZmh-1bLF6ARPw`
	tok, err := jwt.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128GCM})
	if err != nil {
		fmt.Printf("parsing JWT: %s\n", err)
		return
	}

	out := jwt.Claims{}
	if err := tok.Claims(key, &out); err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}
	fmt.Printf("iss: %s, sub: %s\n", out.Issuer, out.Subject)
	// Output: iss: issuer, sub: subject
}

func ExampleParseSignedAndEncrypted() {
	raw := `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIiwiY3R5IjoiSldUIn0..-keV-9YpsxotBEHw.yC9SHWgnkjykgJqXZGlzYC5Wg_EdWKO5TgfqeqsWWJYw7fX9zXQE3NtXmA3nAiUrYOr3H2s0AgTeAhTNbELLEHQu0blfRaPa_uKOAgFgmhJwbGe2iFLn9J0U72wk56318nI-pTLCV8FijoGpXvAxQlaKrPLKkl9yDQimPhb7UiDwLWYkJeoayciAXhR5f40E8ORGjCz8oawXRvjDaSjgRElUwy4kMGzvJy_difemEh4lfMSIwUNVEqJkEYaalRttSymMYuV6NvBVU0N0Jb6omdM4tW961OySB4KPWCWH9UJUX0XSEcqbW9WLxpg3ftx5R7xNiCnaVaCx_gJZfXJ9yFLqztIrKh2N05zHM0tddSOwCOnq7_1rJtaVz0nTXjSjf1RrVaxJya59p3K-e41QutiGFiJGzXG-L2OyLETIaVSU3ptvaCz4IxCF3GzeCvOgaICvXkpBY1-bv-fk1ilyjmcTDnLp2KivWIxcnoQmpN9xj06ZjagdG09AHUhS5WixADAg8mIdGcanNblALecnCWG-otjM9Kw.RZoaHtSgnzOin2od3D9tnA`
	tok, err := jwt.ParseSignedAndEncrypted(raw,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A128GCM},
		[]jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}

	nested, err := tok.Decrypt(sharedEncryptionKey)
	if err != nil {
		fmt.Printf("decrypting JWT: %s\n", err)
		return
	}

	out := jwt.Claims{}
	if err := nested.Claims(&rsaPrivKey.PublicKey, &out); err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}

	fmt.Printf("iss: %s, sub: %s\n", out.Issuer, out.Subject)
	// Output: iss: issuer, sub: subject
}

func ExampleClaims_Validate() {
	cl := jwt.Claims{
		Subject:   "subject",
		Issuer:    "issuer",
		NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:    jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 15, 0, 0, time.UTC)),
		Audience:  jwt.Audience{"leela", "fry"},
	}

	err := cl.Validate(jwt.Expected{
		Issuer: "issuer",
		Time:   time.Date(2016, 1, 1, 0, 10, 0, 0, time.UTC),
	})
	if err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}

	fmt.Printf("valid!")
	// Output: valid!
}

func ExampleClaims_Validate_withParse() {
	raw := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.OFD0iVfPczqWBA_TRi1jGB5PF699eekcHt4D6qNoimc`
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		fmt.Printf("parsing JWT: %s\n", err)
		return
	}

	cl := jwt.Claims{}
	if err := tok.Claims(sharedKey, &cl); err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}

	err = cl.Validate(jwt.Expected{
		Issuer:  "issuer",
		Subject: "subject",
	})
	if err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}

	fmt.Printf("valid!")
	// Output: valid!
}

func ExampleSigned() {
	key := []byte("0102030405060708090A0B0C0D0E0F10")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		fmt.Printf("making signer: %s\n", err)
		return
	}

	cl := jwt.Claims{
		Subject:   "subject",
		Issuer:    "issuer",
		NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		Audience:  jwt.Audience{"leela", "fry"},
	}
	raw, err := jwt.Signed(sig).Claims(cl).Serialize()
	if err != nil {
		fmt.Printf("signing JWT: %s\n", err)
		return
	}

	fmt.Println(raw)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibGVlbGEiLCJmcnkiXSwiaXNzIjoiaXNzdWVyIiwibmJmIjoxNDUxNjA2NDAwLCJzdWIiOiJzdWJqZWN0In0.qEmW0Ehle1yO9XE7xZooC3AUVDF2NnJFDSgn4_6QzUo
}

func ExampleSigned_privateClaims() {
	key := []byte("0102030405060708090A0B0C0D0E0F10")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		fmt.Printf("making signer: %s\n", err)
		return
	}

	cl := jwt.Claims{
		Subject:   "subject",
		Issuer:    "issuer",
		NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		Audience:  jwt.Audience{"leela", "fry"},
	}

	// When setting private claims, make sure to add struct tags
	// to specify how to serialize the field. The naming behavior
	// should match the encoding/json package otherwise.
	privateCl := struct {
		CustomClaim string `json:"custom"`
	}{
		"custom claim value",
	}

	raw, err := jwt.Signed(sig).Claims(cl).Claims(privateCl).Serialize()
	if err != nil {
		fmt.Printf("signing JWT: %s\n", err)
		return
	}

	fmt.Println(raw)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibGVlbGEiLCJmcnkiXSwiY3VzdG9tIjoiY3VzdG9tIGNsYWltIHZhbHVlIiwiaXNzIjoiaXNzdWVyIiwibmJmIjoxNDUxNjA2NDAwLCJzdWIiOiJzdWJqZWN0In0.m6GDh-23MdwYKmzGHuWLMUcx874cGbyMG7nv-5J1ifk
}

func ExampleEncrypted() {
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: sharedEncryptionKey},
		(&jose.EncrypterOptions{}).WithType("JWT"),
	)
	if err != nil {
		fmt.Printf("making encrypter: %s\n", err)
		return
	}

	cl := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	raw, err := jwt.Encrypted(enc).Claims(cl).Serialize()
	if err != nil {
		fmt.Printf("encrypting JWT: %s\n", err)
		return
	}

	fmt.Println(raw)
}

func ExampleSignedAndEncrypted() {
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       sharedEncryptionKey,
		},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if err != nil {
		fmt.Printf("making encrypter: %s\n", err)
		return
	}

	cl := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	raw, err := jwt.SignedAndEncrypted(rsaSigner, enc).Claims(cl).Serialize()
	if err != nil {
		fmt.Printf("encrypting and signing JWT: %s\n", err)
		return
	}

	fmt.Println(raw)
}

func ExampleSigned_multipleClaims() {
	c := &jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	c2 := struct {
		Scopes []string
	}{
		[]string{"foo", "bar"},
	}
	raw, err := jwt.Signed(signer).Claims(c).Claims(c2).Serialize()
	if err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}

	fmt.Println(raw)
	// Output: eyJhbGciOiJIUzI1NiJ9.eyJTY29wZXMiOlsiZm9vIiwiYmFyIl0sImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QifQ.9VjIUvZ8VPFg1mMPq0kTbN7CpVOfn-WChY9RAVu-I6o
}

func ExampleJSONWebToken_Claims_map() {
	raw := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.OFD0iVfPczqWBA_TRi1jGB5PF699eekcHt4D6qNoimc`
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		fmt.Printf("parsing JWT: %s\n", err)
		return
	}

	out := make(map[string]interface{})
	if err := tok.Claims(sharedKey, &out); err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}

	fmt.Printf("iss: %s, sub: %s\n", out["iss"], out["sub"])
	// Output: iss: issuer, sub: subject
}

func ExampleJSONWebToken_Claims_multiple() {
	raw := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzY29wZXMiOlsiczEiLCJzMiJdLCJzdWIiOiJzdWJqZWN0In0.O9XxAYZsxXxWpTftO75vLpyYZ1g7FHxBvyvctGg3Ih0`
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		fmt.Printf("parsing JWT: %s\n", err)
		return
	}

	out := jwt.Claims{}
	out2 := struct {
		Scopes []string `json:"scopes"`
	}{}
	if err := tok.Claims(sharedKey, &out, &out2); err != nil {
		fmt.Printf("validating claims: %s\n", err)
		return
	}
	fmt.Printf("iss: %s, sub: %s, scopes: %s\n", out.Issuer, out.Subject, strings.Join(out2.Scopes, ","))
	// Output: iss: issuer, sub: subject, scopes: s1,s2
}

func mustUnmarshalRSA(data string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode PEM data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse RSA key: " + err.Error())
	}
	if key, ok := key.(*rsa.PrivateKey); ok {
		return key
	}
	panic("key is not of type *rsa.PrivateKey")
}

func mustMakeSigner(alg jose.SignatureAlgorithm, k interface{}) jose.Signer {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, nil)
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}

	return sig
}

var rsaPrivKey = mustUnmarshalRSA(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIHBvDHAr7jh8h
xaqBCl11fjI9YZtdC5b3HtXTXZW3c2dIOImNUjffT8POP6p5OpzivmC1om7iOyuZ
3nJjC9LT3zqqs3f2i5d4mImxEuqG6uWdryFfkp0uIv5VkjVO+iQWd6pDAPGP7r1Z
foXCleyCtmyNH4JSkJneNPOk/4BxO8vcvRnCMT/Gv81IT6H+OQ6OovWOuJr8RX9t
1wuCjC9ezZxeI9ONffhiO5FMrVh5H9LJTl3dPOVa4aEcOvgd45hBmvxAyXqf8daE
6Kl2O7vQ4uwgnSTVXYIIjCjbepuersApIMGx/XPSgiU1K3Xtah/TBvep+S3VlwPc
q/QH25S9AgMBAAECggEAe+y8XKYfPw4SxY1uPB+5JSwT3ON3nbWxtjSIYy9Pqp5z
Vcx9kuFZ7JevQSk4X38m7VzM8282kC/ono+d8yy9Uayq3k/qeOqV0X9Vti1qxEbw
ECkG1/MqGApfy4qSLOjINInDDV+mOWa2KJgsKgdCwuhKbVMYGB2ozG2qfYIlfvlY
vLcBEpGWmswJHNmkcjTtGFIyJgPbsI6ndkkOeQbqQKAaadXtG1xUzH+vIvqaUl/l
AkNf+p4qhPkHsoAWXf1qu9cYa2T8T+mEo79AwlgVC6awXQWNRTiyClDJC7cu6NBy
ZHXCLFMbalzWF9qeI2OPaFX2x3IBWrbyDxcJ4TSdQQKBgQD/Fp/uQonMBh1h4Vi4
HlxZdqSOArTitXValdLFGVJ23MngTGV/St4WH6eRp4ICfPyldsfcv6MZpNwNm1Rn
lB5Gtpqpby1dsrOSfvVbY7U3vpLnd8+hJ/lT5zCYt5Eor46N6iWRkYWzNe4PixiF
z1puGUvFCbZdeeACVrPLmW3JKQKBgQDI0y9WTf8ezKPbtap4UEE6yBf49ftohVGz
p4iD6Ng1uqePwKahwoVXKOc179CjGGtW/UUBORAoKRmxdHajHq6LJgsBxpaARz21
COPy99BUyp9ER5P8vYn63lC7Cpd/K7uyMjaz1DAzYBZIeVZHIw8O9wuGNJKjRFy9
SZyD3V0ddQKBgFMdohrWH2QVEfnUnT3Q1rJn0BJdm2bLTWOosbZ7G72TD0xAWEnz
sQ1wXv88n0YER6X6YADziEdQykq8s/HT91F/KkHO8e83zP8M0xFmGaQCOoelKEgQ
aFMIX3NDTM7+9OoUwwz9Z50PE3SJFAJ1n7eEEoYvNfabQXxBl+/dHEKRAoGAPEvU
EaiXacrtg8EWrssB2sFLGU/ZrTciIbuybFCT4gXp22pvXXAHEvVP/kzDqsRhLhwb
BNP6OuSkNziNikpjA5pngZ/7fgZly54gusmW/m5bxWdsUl0iOXVYbeAvPlqGH2me
LP4Pfs1hw17S/cbT9Z1NE31jbavP4HFikeD73SUCgYEArQfuudml6ei7XZ1Emjq8
jZiD+fX6e6BD/ISatVnuyZmGj9wPFsEhY2BpLiAMQHMDIvH9nlKzsFvjkTPB86qG
jCh3D67Os8eSBk5uRC6iW3Fc4DXvB5EFS0W9/15Sl+V5vXAcrNMpYS82OTSMG2Gt
b9Ym/nxaqyTu0PxajXkKm5Q=
-----END PRIVATE KEY-----`)

var rsaSigner = mustMakeSigner(jose.RS256, rsaPrivKey)
