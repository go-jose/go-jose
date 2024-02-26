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
	"fmt"
	"io"
	"os"
)

// Read input from file or stdin
func readInput(path string) ([]byte, error) {
	var bytes []byte
	var err error

	if path != "" {
		bytes, err = os.ReadFile(path)
	} else {
		bytes, err = io.ReadAll(os.Stdin)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to read input: %w", err)
	}
	return bytes, nil
}

// Write output to file or stdin
func writeOutput(path string, data []byte) error {
	var err error

	if path != "" {
		err = os.WriteFile(path, data, 0644)
	} else {
		_, err = os.Stdout.Write(data)
	}

	if err != nil {
		return fmt.Errorf("unable to write output: %w", err)
	}
	return nil
}

// Byte contents of key file
func keyBytes() ([]byte, error) {
	if *keyFile == "" {
		return nil, fmt.Errorf("no key file provided. See -h for usage")
	}
	keyBytes, err := os.ReadFile(*keyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read key file: %w", err)
	}
	return keyBytes, nil
}

// Write new file to current dir
func writeNewFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}
