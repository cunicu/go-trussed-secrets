// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

const (
	DefaultTimeStep    = 30 * time.Second
	HMACMinimumKeySize = 14
)

// TLV tags for credential data.
//
// See: https://github.com/Nitrokey/pynitrokey/blob/3d2495155dd3c56c02625e362a3106d96ca75286/pynitrokey/nk3/secrets_app.py#L226
const (
	tagCredentialID   tlv.Tag = 0x71 // Also known as Name or Label
	tagNameList       tlv.Tag = 0x72
	tagKey            tlv.Tag = 0x73
	tagChallenge      tlv.Tag = 0x74
	tagResponse       tlv.Tag = 0x75
	tagTruncated      tlv.Tag = 0x76
	tagProperties     tlv.Tag = 0x78
	tagInitialCounter tlv.Tag = 0x7A
	tagVersion        tlv.Tag = 0x79
	tagAlgorithm      tlv.Tag = 0x7B

	// Extensions starting from 0x80
	tagPassword     tlv.Tag = 0x80
	tagNewPassword  tlv.Tag = 0x81
	tagPINCounter   tlv.Tag = 0x82
	tagPWSLogin     tlv.Tag = 0x83
	tagPWSPassword  tlv.Tag = 0x84
	tagPWSMetadata  tlv.Tag = 0x85
	tagSerialNumber tlv.Tag = 0x8F
)

// Instruction bytes for commands.
//
// See: https://github.com/Nitrokey/pynitrokey/blob/3d2495155dd3c56c02625e362a3106d96ca75286/pynitrokey/nk3/secrets_app.py#L207
const (
	insPut    iso.Instruction = 0x01 // Register a new OTP credential
	insDelete iso.Instruction = 0x02 // Register a new OTP credential

	insReset iso.Instruction = 0x04 // Remove all stored OTP credentials

	insList      iso.Instruction = 0xA1 // List stored OTP credentials
	insCalculate iso.Instruction = 0xA2 // Calculate an OTP code for the credential
	insValidate  iso.Instruction = 0xA3 //

	insSendRemaining iso.Instruction = 0xA5

	// Place extending commands in 0xBx space
	insVerifyCode iso.Instruction = 0xB1 // Reverse HOTP - verify incoming HOTP code

	insVerifyPIN iso.Instruction = 0xB2 // Authenticate with provided PIN
	insChangePIN iso.Instruction = 0xB3 // Change PIN
	insSetPIN    iso.Instruction = 0xB4 // Set PIN. Can be called only once, directly after factory reset.

	insGetCredential    iso.Instruction = 0xB5 // Get static password entry
	insUpdateCredential iso.Instruction = 0xB7 // Update static password entry
)

type Card struct {
	*iso.Card

	Clock    func() time.Time
	Timestep time.Duration
	Rand     io.Reader

	info *Select
	tx   *iso.Transaction
}

var errUnknownTag = errors.New("unknown tag")

// NewCard initializes a new card.
func NewCard(pcscCard iso.PCSCCard) (*Card, error) {
	isoCard := iso.NewCard(pcscCard)
	isoCard.InsGetRemaining = insSendRemaining

	tx, err := isoCard.NewTransaction()
	if err != nil {
		return nil, fmt.Errorf("failed to initiate transaction: %w", err)
	}

	return &Card{
		Card:     isoCard,
		Clock:    time.Now,
		Timestep: DefaultTimeStep,
		Rand:     rand.Reader,

		tx: tx,
	}, nil
}

// Close terminates the session.
func (c *Card) Close() error {
	if c.tx != nil {
		if err := c.tx.EndTransaction(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Card) send(ins iso.Instruction, p1, p2 byte, tvsCmd ...tlv.TagValue) (tvsResp []tlv.TagValue, err error) {
	data, err := tlv.EncodeSimple(tvsCmd...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode command: %w", err)
	}

	return c.sendRaw(ins, p1, p2, data)
}

func (c *Card) sendRaw(ins iso.Instruction, p1, p2 byte, data []byte) (tvsResp []tlv.TagValue, err error) {
	cmd := &iso.CAPDU{
		Ins:  ins,
		P1:   p1,
		P2:   p2,
		Data: data,
		Ne:   iso.MaxLenRespDataStandard,
	}

	res, err := c.tx.Send(cmd)
	if err != nil {
		return nil, wrapError(err)
	}

	if tvsResp, err = tlv.DecodeSimple(res); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return tvsResp, nil
}
