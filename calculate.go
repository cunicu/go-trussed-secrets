// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"cunicu.li/go-iso7816/encoding/tlv"
)

var ErrNoValuesFound = errors.New("no values found in response")

// Calculate calculates a TOTP, HOTP with using the clock or current counter value.
func (c *Card) Calculate(id string) (Code, error) {
	return c.CalculateWithChallenge(id, ChallengeTOTP(c.Clock(), c.Timestep))
}

// Calculate a TOTP or HMAC by providing a challenge.
func (c *Card) CalculateWithChallenge(id string, challenge []byte) (Code, error) {
	// Unlike in YKOATH, the Trussed secrets app only returns truncated
	// codes for HOTP and TOTP credentials.
	tvs, err := c.send(insCalculate, 0x00, 0x01,
		tlv.New(tagCredentialID, []byte(id)),
		tlv.New(tagChallenge, challenge),
	)
	if err != nil {
		return Code{}, err
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagResponse, tagTruncated:
			digits := int(tv.Value[0])
			hash := tv.Value[1:]
			return Code{
				Digest:    hash,
				Digits:    digits,
				Truncated: tv.Tag == tagTruncated,
			}, nil

		default:
			return Code{}, fmt.Errorf("%w: %x", errUnknownTag, tv.Tag)
		}
	}

	return Code{}, ErrNoValuesFound
}

func ChallengeTOTP(t time.Time, ts time.Duration) []byte {
	counter := t.Unix() / int64(ts.Seconds())
	return binary.BigEndian.AppendUint64(nil, uint64(counter))
}
