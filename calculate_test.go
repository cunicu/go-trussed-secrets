// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestCalculate(t *testing.T) {
	vs := vectorsTOTP
	vs = append(vs, vectorsHOTP...)

	withCard(t, vs, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		for _, v := range vs {
			chal := secrets.ChallengeTOTP(v.Time, secrets.DefaultTimeStep)
			code, err := card.CalculateWithChallenge(v.ID, chal)
			require.NoError(err)
			require.Equal(v.Code, code.OTP())
		}
	})
}

// func TestCalculateRequireTouch(t *testing.T) {
// 	withCard(t, []vector{
// 		{
// 			ID:         "touch-required",
// 			Algorithm:  secrets.HMACSHA256,
// 			Kind:       secrets.TOTP,
// 			Digits:     6,
// 			Secret:     fromHex("12341234"),
// 			Properties: secrets.TouchRequired,
// 		},
// 	}, true, func(t *testing.T, card *secrets.Card) {
// 		require := require.New(t)

// 		// Callback missing
// 		_, err := card.Calculate("touch-required")
// 		require.ErrorIs(err, secrets.ErrTouchCallbackRequired)

// 		// Error raised in callback
// 		_, err = card.Calculate("touch-required", func(s string) error {
// 			return errors.New("my error") //nolint:goerr113
// 		})
// 		require.ErrorContains(err, "my error")

// 		// Callback called but button not pressed
// 		touchRequested := false
// 		_, err = card.Calculate("touch-required", func(s string) error {
// 			require.Equal(s, "touch-required")
// 			touchRequested = true
// 			return nil
// 		})
// 		require.NoError(err)
// 		require.True(touchRequested)
// 	})
// }

func TestCalculateTOTP(t *testing.T) {
	v := vectorsTOTP[0]
	withCard(t, []vector{v}, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		code, err := card.Calculate(v.ID)
		require.NoError(err)
		require.Equal(v.Code, code)
	})
}

func TestCalculateHOTPCounterIncrement(t *testing.T) {
	v := vectorsHOTP[0]
	withCard(t, []vector{v}, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		for _, ev := range vectorsHOTP[:10] {
			code, err := card.Calculate(v.ID)
			require.NoError(err)
			require.Equal(ev.Code, code.OTP())
			require.Equal(v.Digits, code.Digits)
			require.True(code.Truncated)
		}
	})
}

func TestCalculateHOTPCounterInit(t *testing.T) {
	withCard(t, vectorsHOTP, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		for _, v := range vectorsHOTP {
			code, err := card.Calculate(v.ID)
			require.NoError(err)
			require.Equal(v.Code, code.OTP())
			require.Equal(v.Digits, code.Digits)
			require.True(code.Truncated)
		}
	})
}

// func TestCalculateHMAC(t *testing.T) {
// 	expResp := fromHex("28c6d33a03e7c67940c30d06253f8980f8ef54bd")

// 	v := vector{
// 		ID:        "hmac-test-01",
// 		Algorithm: secrets.HMACSHA1,
// 		Kind:      secrets.HMAC,
// 		Secret:    testSecretSHA1,
// 	}

// 	withCard(t, []vector{v}, true, func(t *testing.T, card *secrets.Card) {
// 		require := require.New(t)

// 		code, err := card.CalculateWithChallenge(v.ID, fromString("hallo"))
// 		require.NoError(err)
// 		require.Equal(expResp, code.Hash)
// 		require.False(code.Truncated)
// 		require.Zero(code.Digits)

// 		hash := v.Algorithm.Hash()()
// 		require.Len(code.Hash, hash.Size())
// 	})
// }
