// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestOTP(t *testing.T) {
	require := require.New(t)
	for _, v := range vectors["HOTP"] {
		c := secrets.Code{
			Digest: v.Hash,
			Digits: v.Digits,
		}

		require.Equal(v.Code, c.OTP())
	}
}
