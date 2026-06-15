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
	"errors"
	"testing"
)

// failingOpaqueSigner reports a single algorithm but always fails to sign.
type failingOpaqueSigner struct{}

func (failingOpaqueSigner) Public() *JSONWebKey        { return &JSONWebKey{Key: &rsaTestKey.PublicKey} }
func (failingOpaqueSigner) Algs() []SignatureAlgorithm { return []SignatureAlgorithm{RS256} }
func (failingOpaqueSigner) SignPayload([]byte, SignatureAlgorithm) ([]byte, error) {
	return nil, errors.New("sign failed")
}

// failingOpaqueKeyEncrypter reports a single algorithm.
type failingOpaqueKeyEncrypter struct{}

func (failingOpaqueKeyEncrypter) KeyID() string        { return "kid" }
func (failingOpaqueKeyEncrypter) Algs() []KeyAlgorithm { return []KeyAlgorithm{A128KW} }
func (failingOpaqueKeyEncrypter) encryptKey([]byte, KeyAlgorithm) (recipientInfo, error) {
	return recipientInfo{}, errors.New("encrypt failed")
}

func TestOpaqueErrorBranches(t *testing.T) {
	// newOpaqueSigner: requested algorithm not in the signer's Algs().
	if _, err := newOpaqueSigner(ES256, failingOpaqueSigner{}); err != ErrUnsupportedAlgorithm {
		t.Errorf("newOpaqueSigner unsupported alg = %v", err)
	}

	// opaqueSigner.signPayload: underlying SignPayload returns an error.
	os := &opaqueSigner{signer: failingOpaqueSigner{}}
	if _, err := os.signPayload([]byte("x"), RS256); err == nil {
		t.Error("opaqueSigner.signPayload: expected error")
	}

	// newOpaqueKeyEncrypter: requested algorithm not in the encrypter's Algs().
	if _, err := newOpaqueKeyEncrypter(A256KW, failingOpaqueKeyEncrypter{}); err != ErrUnsupportedAlgorithm {
		t.Errorf("newOpaqueKeyEncrypter unsupported alg = %v", err)
	}

	// opaqueKeyDecrypter.decryptKey: merged headers fail to sanitize (kid is a number).
	okd := &opaqueKeyDecrypter{decrypter: makeOpaqueKeyDecrypter(t, rsaTestKey, RSA_OAEP)}
	badHeaders := rawHeader{headerKeyID: rawMsg(`5`)}
	if _, err := okd.decryptKey(badHeaders, &recipientInfo{}, nil); err == nil {
		t.Error("opaqueKeyDecrypter.decryptKey with unsanitizable headers: expected error")
	}
}
