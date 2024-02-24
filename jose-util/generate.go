/*-
 * Copyright 2019 Square Inc.
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

package main

import (
	"crypto"
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jose-util/generator"
)

func generate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	generateUseFlag := fs.String("use", "", "Desired public key usage (use header), one of [enc sig]")
	generateAlgFlag := fs.String("alg", "", "Desired key pair algorithm (alg header)")
	generateKeySizeFlag := fs.Int("size", 0, "Key size in bits (e.g. 2048 if generating an RSA key)")
	generateKeyIdentFlag := fs.String("kid", "", "Optional Key ID (kid header, generate random kid if not set)")
	fs.Parse(args)

	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var err error

	switch *generateUseFlag {
	case "sig":
		pubKey, privKey, err = generator.NewSigningKey(jose.SignatureAlgorithm(*generateAlgFlag), *generateKeySizeFlag)
	case "enc":
		pubKey, privKey, err = generator.NewEncryptionKey(jose.KeyAlgorithm(*generateAlgFlag), *generateKeySizeFlag)
	default:
		// According to RFC 7517 section-8.2.  This is unlikely to change in the
		// near future. If it were, new values could be found in the registry under
		// "JSON Web Key Use": https://www.iana.org/assignments/jose/jose.xhtml
		return fmt.Errorf("invalid key use '%s'.  Must be \"sig\" or \"enc\"", *generateUseFlag)
	}
	if err != nil {
		return fmt.Errorf("unable to generate key: %w", err)
	}

	kid := *generateKeyIdentFlag

	priv := jose.JSONWebKey{Key: privKey, KeyID: kid, Algorithm: *generateAlgFlag, Use: *generateUseFlag}

	// Generate a canonical kid based on RFC 7638
	if kid == "" {
		thumb, err := priv.Thumbprint(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("unable to compute thumbprint: %w", err)
		}

		kid = base64.URLEncoding.EncodeToString(thumb)
		priv.KeyID = kid
	}

	// I'm not sure why we couldn't use `pub := priv.Public()` here as the private
	// key should contain the public key.  In case for some reason it doesn't,
	// this builds a public JWK from scratch.
	pub := jose.JSONWebKey{Key: pubKey, KeyID: kid, Algorithm: *generateAlgFlag, Use: *generateUseFlag}

	if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
		// This should never happen
		panic("invalid keys were generated")
	}

	privJSON, err := priv.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal private key to JSON: %w", err)
	}
	pubJSON, err := pub.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal public key to JSON: %w", err)
	}

	name := fmt.Sprintf("jwk-%s-%s", *generateUseFlag, kid)
	pubFile := fmt.Sprintf("%s-pub.json", name)
	privFile := fmt.Sprintf("%s-priv.json", name)

	err = writeNewFile(pubFile, pubJSON, 0444)
	if err != nil {
		return fmt.Errorf("error on write to file %s: %w", pubFile, err)
	}

	err = writeNewFile(privFile, privJSON, 0400)
	if err != nil {
		return fmt.Errorf("error on write to file %s: %w", privFile, err)
	}

	return nil
}
