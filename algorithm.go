// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// Algorithm denotes the HMAC algorithm used for deriving the one-time passwords
type Algorithm byte

const (
	// HMACSHA1 describes a HMAC with SHA-1.
	HMACSHA1 Algorithm = 0x01

	// HMACSHA256 describes a HMAC with SHA-2 (256-bit).
	HMACSHA256 Algorithm = 0x02

	// HMACSHA512 describes a HMAC with SHA-2 (512-bit).
	// TODO: Not yet supported by firmware.
	HMACSHA512 Algorithm = 0x03
)

// String returns a string representation of the algorithm.
func (a Algorithm) String() string {
	switch a {
	case HMACSHA1:
		return "HMAC-SHA1"

	case HMACSHA256:
		return "HMAC-SHA256"

	case HMACSHA512:
		return "HMAC-SHA512"

	default:
		return fmt.Sprintf("unknown %x", byte(a))
	}
}

// Hash returns a constructor to create a new hash.Hash object
// for the given algorithm.
func (a Algorithm) Hash() func() hash.Hash {
	switch a {
	case HMACSHA1:
		return sha1.New

	case HMACSHA256:
		return sha256.New

	case HMACSHA512:
		return sha512.New

	default:
		return nil
	}
}
