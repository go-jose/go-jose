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

func encrypt() {
	pub, err := generator.LoadPublicKey(keyBytes())
	app.FatalIfError(err, "unable to read public key")

	alg := jose.KeyAlgorithm(*encryptAlgFlag)
	enc := jose.ContentEncryption(*encryptEncFlag)

	crypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: pub}, nil)
	app.FatalIfError(err, "unable to instantiate encrypter")

	obj, err := crypter.Encrypt(readInput(*inFile))
	app.FatalIfError(err, "unable to encrypt")

	var msg string
	if *encryptFullFlag {
		msg = obj.FullSerialize()
	} else {
		msg, err = obj.CompactSerialize()
		app.FatalIfError(err, "unable to serialize message")
	}

	writeOutput(*outFile, []byte(msg))
}

func decrypt() {
	priv, err := generator.LoadPrivateKey(keyBytes())
	app.FatalIfError(err, "unable to read private key")

	obj, err := jose.ParseEncrypted(string(readInput(*inFile)), allKeyAlgorithms, allContentEncryption)
	app.FatalIfError(err, "unable to parse message")

	plaintext, err := obj.Decrypt(priv)
	app.FatalIfError(err, "unable to decrypt message")

	writeOutput(*outFile, plaintext)
}

func sign() {
	signingKey, err := generator.LoadPrivateKey(keyBytes())
	app.FatalIfError(err, "unable to read private key")

	alg := jose.SignatureAlgorithm(*signAlgFlag)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signingKey}, nil)
	app.FatalIfError(err, "unable to make signer")

	obj, err := signer.Sign(readInput(*inFile))
	app.FatalIfError(err, "unable to sign")

	var msg string
	if *signFullFlag {
		msg = obj.FullSerialize()
	} else {
		msg, err = obj.CompactSerialize()
		app.FatalIfError(err, "unable to serialize message")
	}

	writeOutput(*outFile, []byte(msg))
}

func verify() {
	verificationKey, err := generator.LoadPublicKey(keyBytes())
	app.FatalIfError(err, "unable to read public key")

	obj, err := jose.ParseSigned(string(readInput(*inFile)), allSignatureAlgorithms)
	app.FatalIfError(err, "unable to parse message")

	plaintext, err := obj.Verify(verificationKey)
	app.FatalIfError(err, "invalid signature")

	writeOutput(*outFile, plaintext)
}
