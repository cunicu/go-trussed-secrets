// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	iso "cunicu.li/go-iso7816"
	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestPIN(t *testing.T) {
	withCard(t, nil, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		sel, err := card.Select()
		require.NoError(err)
		require.False(sel.HasActivePIN())
		require.Nil(sel.Challenge)
		require.Nil(sel.Algorithm)

		// VerifyPIN should fail if not PIN is set
		err = card.VerifyPIN([]byte("1234"))
		require.ErrorIs(err, secrets.Error(iso.ErrSecurityStatusNotSatisfied))

		// Adding an unencrypted credential must always succeed
		err = card.PutOTP("unencrypted", secrets.HMACSHA1, secrets.TOTP, 8, testSecretSHA1, 0, 0)
		require.NoError(err)

		// Adding a PIN encrypted credential must fail if no PIN has been set
		err = card.PutOTP("encrypted", secrets.HMACSHA1, secrets.TOTP, 8, testSecretSHA1, secrets.PINEncrypted, 0)
		require.ErrorIs(err, secrets.Error(iso.ErrSecurityStatusNotSatisfied))

		it, err := card.List()
		require.NoError(err)
		require.Len(it, 1)

		// Set PIN
		err = card.SetPIN([]byte("1338"))
		require.NoError(err)

		// Verify PIN
		err = card.VerifyPIN([]byte("1338"))
		require.NoError(err)

		// Adding a PIN encrypted credential must succeed after PIN has been set
		err = card.PutOTP("encrypted", secrets.HMACSHA1, secrets.TOTP, 8, testSecretSHA1, secrets.PINEncrypted, 0)
		require.NoError(err)

		// Verify valid PIN
		err = card.VerifyPIN([]byte("1338"))
		require.NoError(err)

		it, err = card.List()
		require.NoError(err)
		require.Len(it, 2)
	})

	rebootCard(t)

	withCard(t, nil, false, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		sel, err := card.Select()
		require.NoError(err)
		require.True(sel.HasActivePIN())
		require.Equal(uint32(8), sel.PINCounter)
		require.Nil(sel.Challenge)
		require.Nil(sel.Algorithm)

		_, err = card.Calculate("encrypted")
		require.ErrorIs(err, secrets.Error(iso.ErrFileOrAppNotFound))

		err = card.PutOTP("encrypted2", secrets.HMACSHA256, secrets.TOTP, 8, testSecretSHA256, secrets.PINEncrypted, 0)
		require.ErrorIs(err, secrets.Error(iso.ErrSecurityStatusNotSatisfied))

		// Set PIN again should fail
		err = card.SetPIN([]byte("1339"))
		require.ErrorIs(err, secrets.Error(iso.ErrSecurityStatusNotSatisfied))

		// Verify invalid PIN
		err = card.VerifyPIN([]byte("1337"))
		require.ErrorIs(err, secrets.Error(iso.ErrUnspecifiedWarningModified))

		// Verify valid PIN
		err = card.VerifyPIN([]byte("1338"))
		require.NoError(err)

		err = card.PutOTP("encrypted2", secrets.HMACSHA256, secrets.TOTP, 8, testSecretSHA256, secrets.PINEncrypted, 0)
		require.NoError(err)

		// Verify valid PIN
		err = card.VerifyPIN([]byte("1338"))
		require.NoError(err)

		it, err := card.List()
		require.NoError(err)
		require.Len(it, 3)

		err = card.VerifyPIN([]byte("1338"))
		require.NoError(err)

		res, err := card.Calculate("encrypted2")
		require.NoError(err)
		require.Equal("46119246", res)
	})
}
