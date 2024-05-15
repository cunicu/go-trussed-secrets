// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	secrets "cunicu.li/go-trussed-secrets"
)

func TestPutGetCredential(t *testing.T) {
	withCard(t, nil, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		err := card.PutOTP("my-cred", secrets.HMACSHA1, secrets.NotSet, 6, nil, 0, 0)
		require.NoError(err)

		cred, err := card.Get("my-cred")
		require.NoError(err)
		require.Nil(cred.Login)
		require.Nil(cred.Password)
		require.Nil(cred.Metadata)

		newLogin := "stv0g"
		newPassword := "super-s3cr3t-p4ss"
		newMetadata := "{ \"created\": \"2024-05-13T12:34:56\" }"

		err = card.Update("my-cred", &secrets.Credential{
			Login:    &newLogin,
			Password: &newPassword,
			Metadata: &newMetadata,
		})
		require.NoError(err)

		cred, err = card.Get("my-cred")
		require.NoError(err)
		require.Equal(newLogin, cred.Login)
		require.Equal(newPassword, cred.Password)
		require.Equal(newMetadata, cred.Metadata)
	})
}

func countCredentialsWithID(res []*secrets.ListItem, id string) int {
	found := 0
	for _, e := range res {
		if e.ID == id {
			found++
		}
	}
	return found
}

func TestRenameCredential(t *testing.T) {
	withCard(t, nil, true, func(t *testing.T, card *secrets.Card) {
		require := require.New(t)

		err := card.PutOTP("my-cred", secrets.HMACSHA1, secrets.NotSet, 6, nil, 0, 0)
		require.NoError(err)

		res, err := card.List()
		require.NoError(err)

		require.Equal(countCredentialsWithID(res, "my-cred"), 1)

		err = card.Rename("my-cred", "my-new-cred")
		require.NoError(err)

		res, err = card.List()
		require.NoError(err)

		require.Equal(countCredentialsWithID(res, "my-cred"), 0)
		require.Equal(countCredentialsWithID(res, "my-new-cred"), 1)
	})
}
