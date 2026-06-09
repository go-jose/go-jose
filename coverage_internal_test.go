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
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

// rawMsg builds a rawHeader from raw JSON fragments, exercising the internal
// header getters' error and edge branches directly.
func rawMsg(s string) *json.RawMessage {
	return makeRawMessage([]byte(s))
}

func TestErrUnexpectedSignatureAlgorithmError(t *testing.T) {
	e := &ErrUnexpectedSignatureAlgorithm{Got: HS256, expected: []SignatureAlgorithm{RS256}}
	if e.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

func TestRawHeaderGettersErrorBranches(t *testing.T) {
	// getString: non-string value returns ""
	if s := (rawHeader{headerNonce: rawMsg(`5`)}).getNonce(); s != "" {
		t.Errorf("getNonce on number = %q, want \"\"", s)
	}
	// getString on a valid string
	if s := (rawHeader{headerNonce: rawMsg(`"abc"`)}).getNonce(); s != "abc" {
		t.Errorf("getNonce = %q, want abc", s)
	}

	// getByteBuffer error branch (via getAPU/getIV/getP2S/getTag/getAPV)
	for name, h := range map[string]rawHeader{
		"apu": {headerAPU: rawMsg(`5`)},
		"apv": {headerAPV: rawMsg(`5`)},
		"iv":  {headerIV: rawMsg(`5`)},
		"tag": {headerTag: rawMsg(`5`)},
		"p2s": {headerP2S: rawMsg(`5`)},
	} {
		var err error
		switch name {
		case "apu":
			_, err = h.getAPU()
		case "apv":
			_, err = h.getAPV()
		case "iv":
			_, err = h.getIV()
		case "tag":
			_, err = h.getTag()
		case "p2s":
			_, err = h.getP2S()
		}
		if err == nil {
			t.Errorf("get %s on number: expected error", name)
		}
	}
	// nil byteBuffer returns (nil, nil)
	if bb, err := (rawHeader{}).getAPU(); bb != nil || err != nil {
		t.Errorf("getAPU absent = (%v,%v), want (nil,nil)", bb, err)
	}

	// getEPK / getJWK error and nil branches
	if _, err := (rawHeader{headerEPK: rawMsg(`5`)}).getEPK(); err == nil {
		t.Error("getEPK on number: expected error")
	}
	if epk, err := (rawHeader{}).getEPK(); epk != nil || err != nil {
		t.Errorf("getEPK absent = (%v,%v), want (nil,nil)", epk, err)
	}
	if _, err := (rawHeader{headerJWK: rawMsg(`5`)}).getJWK(); err == nil {
		t.Error("getJWK on number: expected error")
	}
	if jwk, err := (rawHeader{}).getJWK(); jwk != nil || err != nil {
		t.Errorf("getJWK absent = (%v,%v), want (nil,nil)", jwk, err)
	}

	// getCritical error, nil, and value branches
	if _, err := (rawHeader{headerCritical: rawMsg(`5`)}).getCritical(); err == nil {
		t.Error("getCritical on number: expected error")
	}
	if c, err := (rawHeader{}).getCritical(); c != nil || err != nil {
		t.Errorf("getCritical absent = (%v,%v), want (nil,nil)", c, err)
	}

	// getP2C error, nil, value
	if _, err := (rawHeader{headerP2C: rawMsg(`"x"`)}).getP2C(); err == nil {
		t.Error("getP2C on string: expected error")
	}
	if v, err := (rawHeader{}).getP2C(); v != 0 || err != nil {
		t.Errorf("getP2C absent = (%v,%v), want (0,nil)", v, err)
	}
	if v, err := (rawHeader{headerP2C: rawMsg(`42`)}).getP2C(); v != 42 || err != nil {
		t.Errorf("getP2C = (%v,%v), want (42,nil)", v, err)
	}

	// getB64 error, nil (default true), value
	if _, err := (rawHeader{headerB64: rawMsg(`"x"`)}).getB64(); err == nil {
		t.Error("getB64 on string: expected error")
	}
	if v, err := (rawHeader{}).getB64(); !v || err != nil {
		t.Errorf("getB64 absent = (%v,%v), want (true,nil)", v, err)
	}
	if v, err := (rawHeader{headerB64: rawMsg(`false`)}).getB64(); v || err != nil {
		t.Errorf("getB64 = (%v,%v), want (false,nil)", v, err)
	}
}

func TestRawHeaderIsSet(t *testing.T) {
	cases := []struct {
		name string
		h    rawHeader
		want bool
	}{
		{"absent", rawHeader{}, false},
		{"nil value", rawHeader{headerNonce: nil}, false},
		{"invalid json", rawHeader{headerNonce: rawMsg(`{`)}, true},
		{"empty string", rawHeader{headerNonce: rawMsg(`""`)}, false},
		{"non-empty string", rawHeader{headerNonce: rawMsg(`"x"`)}, true},
		{"number", rawHeader{headerNonce: rawMsg(`5`)}, true},
	}
	for _, c := range cases {
		if got := c.h.isSet(headerNonce); got != c.want {
			t.Errorf("isSet(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRawHeaderSetAndMerge(t *testing.T) {
	// set error branch: a channel cannot be marshaled to JSON
	h := rawHeader{}
	if err := h.set(headerNonce, make(chan int)); err == nil {
		t.Error("set with unmarshalable value: expected error")
	}
	// set happy path
	if err := h.set(headerKeyID, "kid"); err != nil {
		t.Fatalf("set: %v", err)
	}

	// merge: src nil is a no-op; an already-set key is skipped, a new one copied
	dst := rawHeader{headerAlgorithm: rawMsg(`"RS256"`)}
	dst.merge(nil)
	src := &rawHeader{
		headerAlgorithm: rawMsg(`"HS256"`), // already set -> skipped
		headerKeyID:     rawMsg(`"k"`),     // new -> copied
	}
	dst.merge(src)
	if dst.getString(headerAlgorithm) != "RS256" {
		t.Error("merge overwrote an already-set header")
	}
	if dst.getString(headerKeyID) != "k" {
		t.Error("merge did not copy a new header")
	}
}

func TestRawHeaderSanitizedErrorBranches(t *testing.T) {
	cases := map[string]rawHeader{
		"jwk":            {headerJWK: rawMsg(`5`)},
		"kid":            {headerKeyID: rawMsg(`5`)},
		"alg":            {headerAlgorithm: rawMsg(`5`)},
		"nonce":          {headerNonce: rawMsg(`5`)},
		"x5c notarray":   {headerX5c: rawMsg(`5`)},
		"x5c bad base64": {headerX5c: rawMsg(`["!"]`)},
		"x5c bad cert":   {headerX5c: rawMsg(`["QQ"]`)},
		"extra":          {"custom": rawMsg(`{`)},
	}
	for name, h := range cases {
		if _, err := h.sanitized(); err == nil {
			t.Errorf("sanitized(%s): expected error", name)
		}
	}

	// nil value is skipped; a valid extra header is collected
	h, err := rawHeader{
		headerNonce: nil,
		"custom":    rawMsg(`"v"`),
	}.sanitized()
	if err != nil {
		t.Fatalf("sanitized valid: %v", err)
	}
	if h.ExtraHeaders["custom"] != "v" {
		t.Errorf("ExtraHeaders[custom] = %v, want v", h.ExtraHeaders["custom"])
	}
}

func TestParseCertificateChainErrors(t *testing.T) {
	if _, err := parseCertificateChain([]string{"!"}); err == nil {
		t.Error("parseCertificateChain with invalid base64: expected error")
	}
	if _, err := parseCertificateChain([]string{"QQ"}); err == nil {
		t.Error("parseCertificateChain with non-certificate bytes: expected error")
	}
}

func TestRecipientConstructorErrorBranches(t *testing.T) {
	// Unsupported algorithm and nil-key branches in the recipient/signer constructors.
	if _, err := newRSARecipient("bogus", &rsa.PublicKey{}); err != ErrUnsupportedAlgorithm {
		t.Errorf("newRSARecipient bad alg = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := newRSARecipient(RSA1_5, nil); err == nil {
		t.Error("newRSARecipient nil key: expected error")
	}
	if _, err := newRSASigner("bogus", &rsa.PrivateKey{}); err != ErrUnsupportedAlgorithm {
		t.Errorf("newRSASigner bad alg = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := newRSASigner(RS256, nil); err == nil {
		t.Error("newRSASigner nil key: expected error")
	}
	if _, err := newEd25519Signer("bogus", nil); err != ErrUnsupportedAlgorithm {
		t.Errorf("newEd25519Signer bad alg = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := newEd25519Signer(EdDSA, nil); err == nil {
		t.Error("newEd25519Signer nil key: expected error")
	}
	if _, err := newECDHRecipient("bogus", &ecdsa.PublicKey{}); err != ErrUnsupportedAlgorithm {
		t.Errorf("newECDHRecipient bad alg = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := newECDHRecipient(ECDH_ES, nil); err == nil {
		t.Error("newECDHRecipient nil key: expected error")
	}
	if _, err := newECDSASigner("bogus", &ecdsa.PrivateKey{}); err != ErrUnsupportedAlgorithm {
		t.Errorf("newECDSASigner bad alg = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := newECDSASigner(ES256, nil); err == nil {
		t.Error("newECDSASigner nil key: expected error")
	}
}

func TestMustSerializeJSONPanics(t *testing.T) {
	// nil pointer serializes to "null", which the function rejects
	mustPanic(t, "nil pointer", func() {
		var p *JSONWebKey
		mustSerializeJSON(p)
	})
	// a value that cannot be marshaled at all
	mustPanic(t, "marshal error", func() {
		mustSerializeJSON(make(chan int))
	})
}

func TestBase64JoinWithDotsEmpty(t *testing.T) {
	if s := base64JoinWithDots(); s != "" {
		t.Errorf("base64JoinWithDots() = %q, want empty", s)
	}
}

func TestByteBufferUnmarshalBranches(t *testing.T) {
	// empty string decodes to a nil buffer without error
	var b byteBuffer
	if err := b.UnmarshalJSON([]byte(`""`)); err != nil {
		t.Errorf("UnmarshalJSON empty: %v", err)
	}
	// invalid base64 is an error
	if err := b.UnmarshalJSON([]byte(`"!!!!"`)); err == nil {
		t.Error("UnmarshalJSON invalid base64: expected error")
	}
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected panic", name)
		}
	}()
	fn()
}
