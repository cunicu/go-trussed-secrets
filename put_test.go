// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestPut(t *testing.T) {
	withCard(t, nil, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		err := card.PutOTP("test", secrets.HMACSHA1, secrets.HOTP, 6, []byte{1, 2, 3}, 0, 0)
		require.NoError(err)
	})
}

func TestPutNameTooLong(t *testing.T) {
	withCard(t, nil, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		err := card.PutOTP("0123456789012345678901234567890123456789012345678901234567890123456789", secrets.HMACSHA1, secrets.HOTP, 6, []byte{1, 2, 3}, 0, 0)
		require.ErrorIs(err, secrets.ErrNameTooLong)
	})
}
