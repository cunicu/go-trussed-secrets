// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/binary"
	"fmt"
	"math"
)

type Code struct {
	Digest        []byte
	Digits        int
	Type          Kind
	TouchRequired bool
	Truncated     bool
}

// OTP converts a value into a (6 or 8 digits) one-time password.
//
// See: RFC 4226 Section 5.3 - Generating an HOTP Value: https://datatracker.ietf.org/doc/html/rfc4226#section-5.3
func (c Code) OTP() string {
	var code uint32
	if c.Truncated {
		code = binary.BigEndian.Uint32(c.Digest)
		code = code % uint32(math.Pow10(c.Digits))
	} else {
		hl := len(c.Digest)
		o := c.Digest[hl-1] & 0xf
		code = binary.BigEndian.Uint32(c.Digest[o:o+4]) & ^uint32(1<<31)
	}

	s := fmt.Sprintf("%08d", code)
	return s[len(s)-c.Digits:]
}
