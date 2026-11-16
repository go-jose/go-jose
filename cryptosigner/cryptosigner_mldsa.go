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

	"github.com/go-jose/go-jose/v4"
)

// mldsaAlgs returns the single JOSE signature algorithm an ML-DSA public key
// supports, determined by its parameter set. The second return value reports
// whether pub was an ML-DSA key at all.
func mldsaAlgs(pub crypto.PublicKey) ([]jose.SignatureAlgorithm, bool) {
	key, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return nil, false
	}

	switch key.Parameters() {
	case mldsa.MLDSA44():
		return []jose.SignatureAlgorithm{jose.MLDSA44}, true
	case mldsa.MLDSA65():
		return []jose.SignatureAlgorithm{jose.MLDSA65}, true
	case mldsa.MLDSA87():
		return []jose.SignatureAlgorithm{jose.MLDSA87}, true
	default:
		return nil, false
	}
}
