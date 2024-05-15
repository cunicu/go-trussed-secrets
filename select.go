// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/binary"
	"fmt"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

// Select encapsulates the results of the "SELECT" instruction.
type Select struct {
	Version    iso.Version
	PINCounter uint32
	Salt       []byte
	Challenge  []byte
	Algorithm  []byte
	Serial     []byte
}

func (s *Select) UnmarshalBinary(b []byte) error {
	tvs, err := tlv.DecodeSimple(b)
	if err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagVersion:
			if len(tv.Value) < 3 {
				return iso.ErrWrongLength
			}

			s.Version.Major = int(tv.Value[0])
			s.Version.Minor = int(tv.Value[1])
			s.Version.Patch = int(tv.Value[2])

		case tagPINCounter:
			if len(tv.Value) > 4 {
				return iso.ErrWrongLength
			}

			buf := []byte{}
			for i := 0; i < 4-len(tv.Value); i++ {
				buf = append(buf, 0)
			}
			buf = append(buf, tv.Value...)

			s.PINCounter = binary.BigEndian.Uint32(buf)

		case tagCredentialID:
			s.Salt = tv.Value

		case tagChallenge:
			s.Challenge = tv.Value

		case tagAlgorithm:
			s.Algorithm = tv.Value

		case tagSerialNumber:
			s.Serial = tv.Value

		default:
			return fmt.Errorf("%w (%#x)", errUnknownTag, tv.Tag)
		}
	}

	return nil
}

func (s *Select) HasHealthyPIN() bool {
	return s.PINCounter != 0
}

func (s *Select) SupportsPasswordStorage() bool {
	return !iso.Version{Major: 4, Minor: 11, Patch: 0}.Less(s.Version)
}

func (s *Select) SupportsExtendedList() bool {
	return !iso.Version{Major: 4, Minor: 11, Patch: 0}.Less(s.Version)
}

func (s *Select) HasEncryptedStorage() bool {
	return !iso.Version{Major: 4, Minor: 10, Patch: 0}.Less(s.Version)
}

func (s *Select) IsOldApplicationVersion() bool {
	return s.Version == iso.Version{Major: 0x34, Minor: 0x34, Patch: 0x34}
}

func (s *Select) RequiresAlwaysPIN() bool {
	return s.Version == iso.Version{Major: 4, Minor: 7, Patch: 0}
}

func (s *Select) SupportsChallengeResponse() bool {
	return s.Challenge != nil
}

func (s *Select) HasActivePIN() bool {
	return s.Challenge == nil && s.PINCounter > 0
}

// Select sends a "SELECT" instruction, initializing the device for an OATH session.
func (c *Card) Select() (*Select, error) {
	resp, err := c.Card.Select(iso.AidYubicoOATH)
	if err != nil {
		return nil, wrapError(err)
	}

	s := &Select{}
	if err := s.UnmarshalBinary(resp); err != nil {
		return nil, err
	}

	c.info = s

	return s, nil
}
