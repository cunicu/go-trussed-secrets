// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import "cunicu.li/go-iso7816/encoding/tlv"

// Delete sends a "DELETE" instruction, removing one named OATH credential.
func (c *Card) DeleteCredential(id string) error {
	_, err := c.send(insDelete, 0x00, 0x00, tlv.New(tagCredentialID, []byte(id)))

	return err
}
