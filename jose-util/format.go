/*
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
)

func expand(args []string) error {
	fs := flag.NewFlagSet("expand", flag.ExitOnError)
	expandFormatFlag := fs.String("format", "", "Type of message to expand (JWS or JWE, defaults to JWE)")
	registerCommon(fs)
	fs.Parse(args)

	bytes, err := readInput(*inFile)
	if err != nil {
		return err
	}

	input := string(bytes)

	var serialized string
	switch *expandFormatFlag {
	case "", "JWE":
		var jwe *jose.JSONWebEncryption
		jwe, err = jose.ParseEncrypted(input, allKeyAlgorithms, allContentEncryption)
		if err == nil {
			serialized = jwe.FullSerialize()
		}
	case "JWS":
		var jws *jose.JSONWebSignature
		jws, err = jose.ParseSigned(input, allSignatureAlgorithms)
		if err == nil {
			serialized = jws.FullSerialize()
		}
	}

	if err != nil {
		return fmt.Errorf("unable to expand message: %w", err)
	}
	err = writeOutput(*outFile, []byte(serialized))
	if err != nil {
		return err
	}

	return writeOutput(*outFile, []byte("\n"))
}
