//go:build go1.27

/*-
 * Copyright 2026 The Go JOSE Authors.
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

package cryptosigner

import (
	"crypto"
	"crypto/mldsa"
	"errors"
	"io"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestMLDSAOpaqueRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		alg    jose.SignatureAlgorithm
		params mldsa.Parameters
	}{
		{jose.ML_DSA_44, mldsa.MLDSA44()},
		{jose.ML_DSA_65, mldsa.MLDSA65()},
		{jose.ML_DSA_87, mldsa.MLDSA87()},
	} {
		t.Run(string(tc.alg), func(t *testing.T) {
			key, err := mldsa.GenerateKey(tc.params)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			signer := Opaque(key)

			algs := signer.Algs()
			if len(algs) != 1 || algs[0] != tc.alg {
				t.Fatalf("Algs() = %v; want [%s]", algs, tc.alg)
			}

			joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: tc.alg, Key: signer}, nil)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			payload := []byte("Lorem ipsum dolor sit amet")
			obj, err := joseSigner.Sign(payload)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			msg, err := obj.CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize: %v", err)
			}
			parsed, err := jose.ParseSigned(msg, []jose.SignatureAlgorithm{tc.alg})
			if err != nil {
				t.Fatalf("ParseSigned: %v", err)
			}
			out, err := parsed.Verify(key.PublicKey())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if string(out) != string(payload) {
				t.Errorf("payload = %q; want %q", out, payload)
			}
		})
	}
}

func TestMLDSAOpaqueRejectsMismatchedAlg(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := Opaque(key).SignPayload([]byte("payload"), jose.ML_DSA_87); err == nil {
		t.Error("SignPayload accepted ML-DSA-87 for an ML-DSA-44 key")
	}
}

func TestMLDSAOpaqueAlgsDoesNotPanic(t *testing.T) {
	var nilPub *mldsa.PublicKey
	zeroPub := new(mldsa.PublicKey)

	for _, tc := range []struct {
		name string
		pub  *mldsa.PublicKey
	}{
		{"typed-nil", nilPub},
		{"zero-value", zeroPub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := Opaque(fakeMLDSASigner{pub: tc.pub})
			if algs := signer.Algs(); len(algs) != 0 {
				t.Errorf("Algs() = %v; want empty", algs)
			}
		})
	}
}

type fakeMLDSASigner struct {
	pub crypto.PublicKey
}

func (f fakeMLDSASigner) Public() crypto.PublicKey { return f.pub }

func (f fakeMLDSASigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("fakeMLDSASigner: Sign unexpectedly called")
}
