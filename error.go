// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	iso "cunicu.li/go-iso7816"
)

type Error iso.Code

// Error return the encapsulated error string.
func (e Error) Error() string {
	c := iso.Code(e)
	return c.Error()
}

// IsMore indicates more data that needs to be fetched.
func (e Error) HasMore() bool {
	return iso.Code(e).HasMore()
}

func wrapError(err error) error {
	if err, ok := err.(iso.Code); ok { //nolint:errorlint
		return Error(err)
	}

	return err
}
