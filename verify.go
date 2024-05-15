// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/binary"

	"cunicu.li/go-iso7816/encoding/tlv"
)

// VerifyCode verifies incoming OTP codes (aka reverse HOTP).
func (c *Card) VerifyCode(id string, code int) error {
	resp := binary.BigEndian.AppendUint32(nil, uint32(code))

	_, err := c.send(insVerifyCode, 0x00, 0x00,
		tlv.New(tagCredentialID, id),
		tlv.New(tagResponse, resp),
	)
	return err
}
