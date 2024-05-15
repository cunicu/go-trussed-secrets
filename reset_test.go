// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestReset(t *testing.T) {
	withCard(t, vectorsTOTP[:1], true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		err := card.Reset()
		require.NoError(err)

		creds, err := card.List()
		require.NoError(err)
		require.Len(creds, 0)
	})
}
