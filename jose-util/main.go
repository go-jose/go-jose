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
	"os"
)

var (
	// Util-wide flags
	keyFile *string
	inFile  *string
	outFile *string
)

func registerCommon(fs *flag.FlagSet) {
	keyFile = fs.String("key", "", "Path to key file (if applicable, PEM, DER or JWK format)")
	inFile = fs.String("in", "", "Path to input file (if applicable, stdin if missing)")
	outFile = fs.String("out", "", "Path to output file (if applicable, stdout if missing)")
}

func main() {
	subCommands := map[string]struct {
		desc string
		run  func(args []string) error
	}{
		"encrypt": {
			desc: "Encrypt a plaintext, output ciphertext",
			run:  encrypt,
		},
		"decrypt": {
			desc: "Decrypt a ciphertext, output plaintext",
			run:  decrypt,
		},
		"sign": {
			desc: "Sign a payload, output signed message",
			run:  sign,
		},
		"verify": {
			desc: "Verify a signed message, output payload",
			run:  verify,
		},
		"expand": {
			desc: "Expand JOSE object to JSON Serialization format",
			run:  expand,
		},
		"generate-key": {
			desc: "Generate a public/private key pair in JWK format",
			run:  generate,
		},
	}

	usage := func() {
		fmt.Printf("Usage: jose-utils [subcommand]\nSubcommands:\n")
		for name, command := range subCommands {
			fmt.Printf("  %s\n", name)
			fmt.Printf("\t%s\n", command.desc)
		}
		fmt.Printf("Pass -h to each subcommand for more information")
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		usage()
	}

	cmd, ok := subCommands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid subcommand %s\n", os.Args[1])
		usage()
	}

	err := cmd.run(os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running command: %s\n", err)
		os.Exit(1)
	}
}
