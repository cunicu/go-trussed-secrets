// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"math/rand"
	"testing"
	"time"

	iso "cunicu.li/go-iso7816"
	nk "cunicu.li/go-iso7816/devices/nitrokey"
	"cunicu.li/go-iso7816/filter"
	"cunicu.li/go-iso7816/test"
	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

// rebootCard sends a reboot instruction to the card via the Trussed admin applet.
func rebootCard(t *testing.T) {
	test.WithCard(t, filter.IsNitrokey3, func(t *testing.T, card *iso.Card) {
		require := require.New(t)

		_, err := card.Select(iso.AidSolokeysAdmin)
		require.NoError(err)

		err = nk.Reboot(card)
		require.NoError(err)
	})
}

// withCard is a helper to initialize a card for testing.
func withCard(t *testing.T, vs []vector, reset bool, cb func(t *testing.T, card *secrets.Card)) {
	test.WithCard(t, filter.Any, func(t *testing.T, isoCard *iso.Card) {
		require := require.New(t)

		oathCard, err := secrets.NewCard(isoCard)
		require.NoError(err)

		_, err = oathCard.Select()
		require.NoError(err, "Failed to select applet")

		if reset {
			err = oathCard.Reset()
			require.NoError(err, "Failed to reset applet")
		}

		for _, v := range vs {
			v := v
			err = oathCard.PutOTP(v.ID, v.Algorithm, v.Kind, v.Digits, v.Secret, v.Properties, v.Counter)
			require.NoError(err, "Failed to put credential")
		}

		// Fix the clock for our tests
		oathCard.Clock = func() time.Time {
			return time.Unix(59, 0)
		}

		// Fix the random source for reproducible tests
		oathCard.Rand = rand.New(rand.NewSource(4242)) //nolint:gosec

		cb(t, oathCard)

		err = oathCard.Close()
		require.NoError(err)
	})
}
