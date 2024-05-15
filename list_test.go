// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestList(t *testing.T) {
	withCard(t, vectorsMix, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		res, err := card.List()
		require.NoError(err)
		require.Len(res, len(vectorsMix))

		vs := map[string]*vector{}
		for _, v := range vectorsMix {
			v := v
			vs[v.ID] = &v
		}

		fmt.Println(vs)

		for _, r := range res {
			v, ok := vs[r.ID]
			require.True(ok)

			require.Equal(v.ID, r.ID)
			require.Equal(v.Algorithm, r.Algorithm)
			require.Equal(v.Kind, r.Kind)
			require.Equal(v.Properties, r.Properties)
		}
	})
}
