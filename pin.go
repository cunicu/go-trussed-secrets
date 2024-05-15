// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"errors"

	"cunicu.li/go-iso7816/encoding/tlv"
)

var ErrNoPINSet = errors.New("no PIN has been configured")

// SetPIN sets an initial PIN.
// This command requires no prior authentication.
// No previous PIN must be configured.
func (c *Card) SetPIN(password []byte) error {
	_, err := c.send(insSetPIN, 0x00, 0x00,
		tlv.New(tagPassword, password),
	)
	return err
}

// ChangePIN changes the PIN.
// This command no prior authentication.
// The old password must be provided.
func (c *Card) ChangePIN(oldPassword, newPassword []byte) error {
	_, err := c.send(insChangePIN, 0x00, 0x00,
		tlv.New(tagPassword, oldPassword),
		tlv.New(tagNewPassword, newPassword),
	)
	return err
}

// VerifyPIN checks the provided PIN code.
// This command requires no prior authentication.
func (c *Card) VerifyPIN(password []byte) error {
	_, err := c.send(insVerifyPIN, 0x00, 0x00,
		tlv.New(tagPassword, password),
	)
	return err
}
