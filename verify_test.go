// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"strconv"
	"testing"

	secrets "cunicu.li/go-trussed-secrets"
	"github.com/stretchr/testify/require"
)

func TestVerifyCode(t *testing.T) {
	withCard(t, nil, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		err := card.PutOTP("reverse-hotp", secrets.HMACSHA1, secrets.HOTPReverse, 6, testSecretSHA1, 0, 0)
		require.NoError(err)

		for _, v := range vectorsHOTP {
			code, err := strconv.Atoi(v.Code)
			require.NoError(err)

			err = card.VerifyCode("reverse-hotp", code)
			require.NoError(err)
		}
	})
}
