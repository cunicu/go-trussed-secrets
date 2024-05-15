// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

// Reset resets the application to just-installed state.
// This command requires no authentication.
// WARNING: This function wipes all secrets on the card. Use with care!
func (c *Card) Reset() error {
	_, err := c.send(insReset, 0xde, 0xad)
	return err
}
