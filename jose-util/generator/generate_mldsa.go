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

package generator

import (
	"crypto"
	"crypto/mldsa"

	"github.com/go-jose/go-jose/v4"
)

// newMLDSASigningKey generates an ML-DSA key pair for alg. The parameter set is
// fixed by alg, so no key size argument is meaningful. The third return value
// reports whether alg named an ML-DSA algorithm at all.
func newMLDSASigningKey(alg jose.SignatureAlgorithm) (crypto.PublicKey, crypto.PrivateKey, bool, error) {
	var params mldsa.Parameters

	switch alg {
	case jose.ML_DSA_44:
		params = mldsa.MLDSA44()
	case jose.ML_DSA_65:
		params = mldsa.MLDSA65()
	case jose.ML_DSA_87:
		params = mldsa.MLDSA87()
	default:
		return nil, nil, false, nil
	}

	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, nil, true, err
	}

	return key.PublicKey(), key, true, nil
}
