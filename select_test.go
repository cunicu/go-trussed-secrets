// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	iso "cunicu.li/go-iso7816"
	"github.com/stretchr/testify/assert"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestSelect(t *testing.T) {
	withCard(t, nil, true, func(t *testing.T, card *secrets.Card) {
		assert := assert.New(t)

		res, err := card.Select()
		assert.NoError(err)

		assert.Empty(res.PINCounter)
		assert.Empty(res.Algorithm)
		assert.Empty(res.Challenge)
		assert.Len(res.Salt, 8)
		assert.Len(res.Serial, 4)
		assert.Equal(iso.Version{Major: 0x04, Minor: 0x0d, Patch: 0x00}, res.Version)

		t.Logf("select: %+#v", res)
	})
}
