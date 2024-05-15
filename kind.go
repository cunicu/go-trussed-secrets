// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import "fmt"

const (
	HOTP        Kind = 0x10 // HOTP calculates OTP as HOTP, against the internal counter.
	TOTP        Kind = 0x20 // TOTP calculates OTP as TOTP, against the provided challenge.
	HOTPReverse Kind = 0x30 // HOTPReverse calculates HOTP code, and compare against the provided one.
	HMAC        Kind = 0x40 // HMAC calculates HMAC-challenge value.
	NotSet      Kind = 0xF0 // NotSet is used for password safe entries.
)

// Kind denotes the kind of derivation used for the one-time password.
type Kind byte

// String returns a string representation of the type.
func (t Kind) String() string {
	switch t {
	case HOTP:
		return "HOTP"

	case TOTP:
		return "TOTP"

	case HOTPReverse:
		return "Reverse HOTP"

	case HMAC:
		return "HMAC"

	default:
		return fmt.Sprintf("unknown %x", byte(t))
	}
}
