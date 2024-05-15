// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

type Credential struct {
	ID       string
	Login    *string
	Password *string
	Metadata *string

	Kind      Kind
	Algorithm Algorithm

	Properties *Properties
}

func (c *Credential) Unmarshal(tvs tlv.TagValues) error {
	for _, tv := range tvs {
		switch tv.Tag {
		case tagCredentialID:
			c.ID = string(tv.Value)

		case tagPWSLogin:
			s := string(tv.Value)
			c.Login = &s

		case tagPWSPassword:
			s := string(tv.Value)
			c.Password = &s

		case tagPWSMetadata:
			s := string(tv.Value)
			c.Metadata = &s

		case tagProperties:
			if len(tv.Value) != 1 {
				return iso.ErrWrongLength
			}

			p := Properties(tv.Value[0])
			c.Properties = &p
		}
	}

	return nil
}

func (c *Credential) TagValues() tlv.TagValues {
	tvs := tlv.TagValues{}

	if c.Login != nil {
		tvs = append(tvs, tlv.New(tagPWSLogin, c.Login))
	}

	if c.Password != nil {
		tvs = append(tvs, tlv.New(tagPWSPassword, c.Password))
	}

	if c.Metadata != nil {
		tvs = append(tvs, tlv.New(tagPWSMetadata, c.Metadata))
	}

	if c.Properties != nil {
		tvs = append(tvs, c.Properties.TagValue(false))
	}

	return tvs
}

func (c *Card) Get(id string) (*Credential, error) {
	resp, err := c.send(insGetCredential, 0x00, 0x00, tlv.New(tagCredentialID, id))
	if err != nil {
		return nil, err
	}

	var creds Credential

	if err := creds.Unmarshal(resp); err != nil {
		return nil, err
	}

	return &creds, nil
}

func (c *Card) Rename(oldID, newID string) error {
	_, err := c.send(insUpdateCredential, 0x00, 0x00,
		tlv.New(tagCredentialID, oldID),
		tlv.New(tagCredentialID, newID))

	return err
}

func (c *Card) Update(oldID string, n *Credential) error {
	tvs := tlv.TagValues{tlv.New(tagCredentialID, oldID)}
	tvs = append(tvs, n.TagValues()...)

	_, err := c.send(insUpdateCredential, 0x00, 0x00, tvs...)
	return err
}
