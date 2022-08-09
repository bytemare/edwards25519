// SPDX-License-Identifier: MIT
//
// Copyright (C) 2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package edwards25519_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ed "filippo.io/edwards25519"

	"github.com/bytemare/edwards25519"
)

func TestVectors(t *testing.T) {
	if err := filepath.Walk("vectors",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			v, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var tt tests
			err = json.Unmarshal(v, &tt)
			if err != nil {
				t.Fatal(err)
			}

			t.Run(path, tt.run)

			return nil
		}); err != nil {
		t.Fatalf("error opening vector files: %v", err)
	}
}

type tests struct {
	Ciphersuite string   `json:"ciphersuite"`
	Dst         string   `json:"dst"`
	Vectors     []vector `json:"vectors"`
}

func (tt tests) run(t *testing.T) {
	for id, vector := range tt.Vectors {
		vector.tests = &tt
		t.Run(string(rune(id)), vector.run)
	}
}

type vector struct {
	*tests
	P struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"P"`
	Msg string `json:"msg"`
}

func reverse(b []byte) []byte {
	l := len(b) - 1
	for i := 0; i < len(b)/2; i++ {
		b[i], b[l-i] = b[l-i], b[i]
	}

	return b
}

func decodeEd25519(x, y string) []byte {
	xb, err := hex.DecodeString(x)
	if err != nil {
		panic(err)
	}

	yb, err := hex.DecodeString(y)
	if err != nil {
		panic(err)
	}

	yb = reverse(yb)
	isXNeg := int(xb[31] & 1)
	yb[31] |= byte(isXNeg << 7)

	// Test if serialization works.
	q, err := ed.NewIdentityPoint().SetBytes(yb)
	if err != nil {
		panic(err)
	}

	return q.Bytes()
}

func (v *vector) run(t *testing.T) {
	expected := hex.EncodeToString(decodeEd25519(v.P.X[2:], v.P.Y[2:]))

	switch v.Ciphersuite[len(v.Ciphersuite)-3:] {
	case "RO_":
		p := edwards25519.HashToEdwards25519([]byte(v.Msg), []byte(v.Dst))

		if hex.EncodeToString(p.Bytes()) != expected {
			t.Fatalf("Unexpected HashToGroup output.\n\tExpected %q\n\tgot %q", expected, hex.EncodeToString(p.Bytes()))
		}
	case "NU_":
		p := edwards25519.EncodeToEdwards25519([]byte(v.Msg), []byte(v.Dst))

		if hex.EncodeToString(p.Bytes()) != expected {
			t.Fatalf("Unexpected EncodeToGroup output.\n\tExpected %q\n\tgot %q", expected, hex.EncodeToString(p.Bytes()))
		}
	default:
		t.Fatal("ciphersuite not recognized")
	}
}
