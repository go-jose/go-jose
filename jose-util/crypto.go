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
	"flag"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jose-util/generator"
)

var allKeyAlgorithms = []jose.KeyAlgorithm{
	jose.ED25519,
	jose.RSA1_5,
	jose.RSA_OAEP,
	jose.RSA_OAEP_256,
	jose.A128KW,
	jose.A192KW,
	jose.A256KW,
	jose.DIRECT,
	jose.ECDH_ES,
	jose.ECDH_ES_A128KW,
	jose.ECDH_ES_A192KW,
	jose.ECDH_ES_A256KW,
	jose.A128GCMKW,
	jose.A192GCMKW,
	jose.A256GCMKW,
	jose.PBES2_HS256_A128KW,
	jose.PBES2_HS384_A192KW,
	jose.PBES2_HS512_A256KW,
}

var allSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.HS256,
	jose.HS384,
	jose.HS512,
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
}

var allContentEncryption = []jose.ContentEncryption{
	jose.A128CBC_HS256,
	jose.A192CBC_HS384,
	jose.A256CBC_HS512,
	jose.A128GCM,
	jose.A192GCM,
	jose.A256GCM,
}

func encrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	encryptAlgFlag := fs.String("alg", "", "Key management algorithm (e.g. RSA-OAEP)")
	encryptEncFlag := fs.String("enc", "", "Content encryption algorithm (e.g. A128GCM)")
	encryptFullFlag := fs.Bool("full", false, "Use JSON Serialization format (instead of compact)")
	registerCommon(fs)
	err := fs.Parse(args)

	bytes, err := keyBytes()
	if err != nil {
		return err
	}

	pub, err := generator.LoadPublicKey(bytes)
	if err != nil {
		return fmt.Errorf("unable to read public key: %w", err)
	}

	alg := jose.KeyAlgorithm(*encryptAlgFlag)
	enc := jose.ContentEncryption(*encryptEncFlag)

	crypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: pub}, nil)
	if err != nil {
		return fmt.Errorf("unable to instantiate encrypter: %w", err)
	}

	input, err := readInput(*inFile)
	if err != nil {
		return err
	}

	obj, err := crypter.Encrypt(input)
	if err != nil {
		return fmt.Errorf("unable to encrypt: %w", err)
	}

	var msg string
	if *encryptFullFlag {
		msg = obj.FullSerialize()
	} else {
		msg, err = obj.CompactSerialize()
		if err != nil {
			return fmt.Errorf("unable to serialzie message: %w", err)
		}
	}

	return writeOutput(*outFile, []byte(msg))
}

func decrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	registerCommon(fs)
	fs.Parse(args)

	bytes, err := keyBytes()
	if err != nil {
		return err
	}

	priv, err := generator.LoadPrivateKey(bytes)
	if err != nil {
		return fmt.Errorf("unable to read private key %s: %w", priv, err)
	}

	input, err := readInput(*inFile)
	if err != nil {
		return err
	}

	obj, err := jose.ParseEncrypted(string(input), allKeyAlgorithms, allContentEncryption)
	if err != nil {
		return fmt.Errorf("unable to parse message: %w", err)
	}

	plaintext, err := obj.Decrypt(priv)
	if err != nil {
		return fmt.Errorf("unable to decrypt message: %w", err)
	}

	return writeOutput(*outFile, plaintext)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	signAlgFlag := fs.String("alg", "", "Key management algorithm (e.g. RSA-OAEP)")
	signFullFlag := fs.Bool("full", false, "Use JSON Serialization format (instead of compact)")
	registerCommon(fs)
	fs.Parse(args)

	bytes, err := keyBytes()
	if err != nil {
		return err
	}

	signingKey, err := generator.LoadPrivateKey(bytes)
	if err != nil {
		return fmt.Errorf("unable to read private key: %w", err)
	}

	alg := jose.SignatureAlgorithm(*signAlgFlag)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signingKey}, nil)
	if err != nil {
		return fmt.Errorf("unable to make signer: %w", err)
	}

	input, err := readInput(*inFile)
	if err != nil {
		return err
	}

	obj, err := signer.Sign(input)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	var msg string
	if *signFullFlag {
		msg = obj.FullSerialize()
	} else {
		msg, err = obj.CompactSerialize()
		if err != nil {
			return fmt.Errorf("unable to serialize message: %w", err)
		}
	}

	return writeOutput(*outFile, []byte(msg))
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	registerCommon(fs)
	fs.Parse(args)

	bytes, err := keyBytes()
	if err != nil {
		return err
	}

	verificationKey, err := generator.LoadPublicKey(bytes)
	if err != nil {
		return fmt.Errorf("unable to read public key: %w", err)
	}

	input, err := readInput(*inFile)
	if err != nil {
		return err
	}

	obj, err := jose.ParseSigned(string(input), allSignatureAlgorithms)
	if err != nil {
		return fmt.Errorf("unable to parse message: %w", err)
	}

	plaintext, err := obj.Verify(verificationKey)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	return writeOutput(*outFile, plaintext)
}
