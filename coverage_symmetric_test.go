/*-
 * Copyright 2024 go-jose authors
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
	"testing"
)

func TestSymmetricDecryptKeyErrorBranches(t *testing.T) {
	c16 := &symmetricKeyCipher{key: make([]byte, 16)}
	cBad := &symmetricKeyCipher{key: make([]byte, 5)} // invalid AES key size
	ek := []byte("0123456789abcdef")                  // 16 bytes of junk

	hdr := func(pairs ...string) rawHeader {
		h := rawHeader{}
		for i := 0; i+1 < len(pairs); i += 2 {
			h[HeaderKey(pairs[i])] = rawMsg(pairs[i+1])
		}
		return h
	}

	cases := []struct {
		name      string
		cipher    *symmetricKeyCipher
		headers   rawHeader
		recipient *recipientInfo
	}{
		{"nil recipient", c16, hdr("alg", `"A128KW"`), nil},
		{"missing encrypted key", c16, hdr("alg", `"A128KW"`), &recipientInfo{}},
		{"gcmkw bad iv", c16, hdr("alg", `"A128GCMKW"`, "iv", `5`), &recipientInfo{encryptedKey: ek}},
		{"gcmkw bad tag", c16, hdr("alg", `"A128GCMKW"`, "iv", `"AAAA"`, "tag", `5`), &recipientInfo{encryptedKey: ek}},
		{"gcmkw decrypt fail", c16, hdr("alg", `"A128GCMKW"`, "iv", `"AAAAAAAAAAAAAAAA"`, "tag", `"AAAAAAAAAAAAAAAAAAAAAA"`), &recipientInfo{encryptedKey: ek}},
		{"kw bad key size", cBad, hdr("alg", `"A128KW"`), &recipientInfo{encryptedKey: ek}},
		{"kw unwrap fail", c16, hdr("alg", `"A128KW"`), &recipientInfo{encryptedKey: ek}},
		{"pbes2 missing p2s", c16, hdr("alg", `"PBES2-HS256+A128KW"`), &recipientInfo{encryptedKey: ek}},
		{"pbes2 bad p2s", c16, hdr("alg", `"PBES2-HS256+A128KW"`, "p2s", `5`), &recipientInfo{encryptedKey: ek}},
		{"pbes2 bad p2c", c16, hdr("alg", `"PBES2-HS256+A128KW"`, "p2s", `"AAAA"`, "p2c", `"x"`), &recipientInfo{encryptedKey: ek}},
		{"pbes2 p2c zero", c16, hdr("alg", `"PBES2-HS256+A128KW"`, "p2s", `"AAAA"`, "p2c", `0`), &recipientInfo{encryptedKey: ek}},
		{"pbes2 p2c too high", c16, hdr("alg", `"PBES2-HS256+A128KW"`, "p2s", `"AAAA"`, "p2c", `2000000`), &recipientInfo{encryptedKey: ek}},
		{"pbes2 unwrap fail", c16, hdr("alg", `"PBES2-HS256+A128KW"`, "p2s", `"AAAA"`, "p2c", `1000`), &recipientInfo{encryptedKey: ek}},
		{"unsupported alg", c16, hdr("alg", `"BOGUS"`), &recipientInfo{encryptedKey: ek}},
	}
	for _, c := range cases {
		if _, err := c.cipher.decryptKey(c.headers, c.recipient, nil); err == nil {
			t.Errorf("decryptKey(%s): expected error", c.name)
		}
	}

	// DIRECT returns a clone of the key with no error.
	got, err := c16.decryptKey(hdr("alg", `"dir"`), &recipientInfo{}, nil)
	if err != nil || len(got) != 16 {
		t.Errorf("decryptKey(dir) = (%v,%v)", got, err)
	}
}

func TestContentCipherBadKey(t *testing.T) {
	// getAead fails for an invalid key length, in both encrypt and decrypt.
	for _, enc := range []ContentEncryption{A128GCM, A128CBC_HS256} {
		cipher := getContentCipher(enc)
		if cipher == nil {
			t.Fatalf("no cipher for %s", enc)
		}
		if _, err := cipher.encrypt(make([]byte, 3), nil, []byte("pt")); err == nil {
			t.Errorf("%s encrypt with bad key: expected error", enc)
		}
		parts := &aeadParts{iv: make([]byte, 12), ciphertext: []byte("x"), tag: make([]byte, 16)}
		if _, err := cipher.decrypt(make([]byte, 3), nil, parts); err == nil {
			t.Errorf("%s decrypt with bad key: expected error", enc)
		}
	}
}

func TestSymmetricEncryptKeyErrorBranches(t *testing.T) {
	cBad := &symmetricKeyCipher{key: make([]byte, 5)} // invalid AES key size
	cek := make([]byte, 16)

	// A128KW with an invalid key size -> aes.NewCipher error.
	if _, err := cBad.encryptKey(cek, A128KW); err == nil {
		t.Error("encryptKey A128KW with bad key size: expected error")
	}
}
