// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestDelete(t *testing.T) {
	vs := vectorsTOTP[:1]
	withCard(t, vs, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		creds, err := card.List()
		require.NoError(err)
		require.Len(creds, 1)

		err = card.DeleteCredential(vs[0].ID)
		require.NoError(err)

		creds, err = card.List()
		require.NoError(err)
		require.Len(creds, 0)
	})
}
