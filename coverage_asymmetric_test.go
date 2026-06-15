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

	"github.com/go-jose/go-jose/v4/json"
)

func epkHeader(t *testing.T, key interface{}) *json.RawMessage {
	t.Helper()
	b, err := (&JSONWebKey{Key: key}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return makeRawMessage(b)
}

func TestAsymmetricUnsupportedAlgBranches(t *testing.T) {
	// RSA verifyPayload, unsupported alg.
	rv := rsaEncrypterVerifier{publicKey: &rsaTestKey.PublicKey}
	if err := rv.verifyPayload(nil, nil, "BOGUS"); err != ErrUnsupportedAlgorithm {
		t.Errorf("rsa verifyPayload bad alg = %v", err)
	}

	// EC encryptKey, unsupported alg.
	ev := ecEncrypterVerifier{publicKey: &ecTestKey256.PublicKey}
	if _, err := ev.encryptKey(nil, "BOGUS"); err != ErrUnsupportedAlgorithm {
		t.Errorf("ec encryptKey bad alg = %v", err)
	}

	// Ed25519 signPayload / verifyPayload.
	eds := edDecrypterSigner{privateKey: ed25519PrivateKey}
	if _, err := eds.signPayload(nil, "BOGUS"); err != ErrUnsupportedAlgorithm {
		t.Errorf("ed signPayload bad alg = %v", err)
	}
	edv := edEncrypterVerifier{publicKey: ed25519PublicKey}
	if err := edv.verifyPayload(nil, nil, "BOGUS"); err != ErrUnsupportedAlgorithm {
		t.Errorf("ed verifyPayload bad alg = %v", err)
	}
	if err := edv.verifyPayload([]byte("x"), make([]byte, 64), EdDSA); err == nil {
		t.Error("ed verifyPayload with bad signature: expected error")
	}

	// EC signPayload: bit-size mismatch and unsupported alg (size 0 != curve).
	es := ecDecrypterSigner{privateKey: ecTestKey256}
	if _, err := es.signPayload([]byte("x"), ES384); err == nil {
		t.Error("ec signPayload with mismatched curve: expected error")
	}
	if _, err := es.signPayload([]byte("x"), "BOGUS"); err == nil {
		t.Error("ec signPayload with unsupported alg: expected error")
	}
}

func TestECDecryptKeyErrorBranches(t *testing.T) {
	ds := ecDecrypterSigner{privateKey: ecTestKey256}
	rec := &recipientInfo{encryptedKey: []byte("x")}

	// nil recipient
	if _, err := ds.decryptKey(rawHeader{}, nil, nil); err == nil {
		t.Error("decryptKey nil recipient: expected error")
	}
	// invalid epk header (not a JWK)
	if _, err := ds.decryptKey(rawHeader{headerEPK: rawMsg(`5`)}, rec, nil); err == nil {
		t.Error("decryptKey invalid epk: expected error")
	}
	// missing epk header
	if _, err := ds.decryptKey(rawHeader{}, rec, nil); err == nil {
		t.Error("decryptKey missing epk: expected error")
	}
	// epk present but not an EC key
	if _, err := ds.decryptKey(rawHeader{headerEPK: epkHeader(t, &rsaTestKey.PublicKey)}, rec, nil); err == nil {
		t.Error("decryptKey non-EC epk: expected error")
	}
	// epk on a different curve -> not on this private key's curve
	if _, err := ds.decryptKey(rawHeader{headerEPK: epkHeader(t, &ecTestKey384.PublicKey)}, rec, nil); err == nil {
		t.Error("decryptKey cross-curve epk: expected error")
	}
	// valid epk, malformed apu / apv
	good := epkHeader(t, &ecTestKey256.PublicKey)
	if _, err := ds.decryptKey(rawHeader{headerEPK: good, headerAPU: rawMsg(`5`)}, rec, nil); err == nil {
		t.Error("decryptKey invalid apu: expected error")
	}
	if _, err := ds.decryptKey(rawHeader{headerEPK: good, headerAPV: rawMsg(`5`)}, rec, nil); err == nil {
		t.Error("decryptKey invalid apv: expected error")
	}
}

func TestGetPbkdf2ParamsPanic(t *testing.T) {
	mustPanic(t, "getPbkdf2Params unsupported alg", func() {
		getPbkdf2Params("BOGUS")
	})
}
