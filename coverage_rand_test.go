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
	"bytes"
	"testing"
)

// TestBrokenRandFailures exercises the "random source failed" error branches in
// the low-level crypto, which are otherwise unreachable with a working RNG.
func TestBrokenRandFailures(t *testing.T) {
	defer resetRandReader()
	broken := func() { randReader = bytes.NewReader([]byte{}) }

	// AEAD content cipher: IV generation fails.
	broken()
	if _, err := getContentCipher(A128GCM).encrypt(make([]byte, 16), nil, []byte("pt")); err == nil {
		t.Error("content cipher encrypt with broken rand: expected error")
	}

	// Symmetric AES-GCM key wrap: IV generation fails.
	broken()
	if _, err := (&symmetricKeyCipher{key: make([]byte, 16)}).encryptKey(make([]byte, 16), A128GCMKW); err == nil {
		t.Error("symmetric encryptKey with broken rand: expected error")
	}

	// ECDH ephemeral key generation fails (also covers ecKeyGenerator.genKey).
	broken()
	ev := ecEncrypterVerifier{publicKey: &ecTestKey256.PublicKey}
	if _, err := ev.encryptKey(make([]byte, 16), ECDH_ES_A128KW); err == nil {
		t.Error("ec encryptKey with broken rand: expected error")
	}

	// ECDSA signing fails when the RNG is broken.
	broken()
	es := ecDecrypterSigner{privateKey: ecTestKey256}
	if _, err := es.signPayload([]byte("payload"), ES256); err == nil {
		t.Error("ec signPayload with broken rand: expected error")
	}
}
