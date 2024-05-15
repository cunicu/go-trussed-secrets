// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/binary"
	"errors"
	"fmt"

	"cunicu.li/go-iso7816/encoding/tlv"
)

var (
	ErrNameTooLong           = errors.New("name too long)")
	ErrInvalidNumberOfDigits = errors.New("number of digits must be 6 or 8")
)

// PutPasswords adds a mew password safe.
func (c *Card) PutPassword(id string, props Properties) error {
	return c.PutOTP(id, HMACSHA1, NotSet, 6, padKey(nil), props, 0)
}

// PutOTP adds a new OTP credential.
func (c *Card) PutOTP(id string, alg Algorithm, kind Kind, digits int, secret []byte, props Properties, counter uint32) error {
	if l := len(id); l > 64 {
		return fmt.Errorf("%w: (%d > 64)", ErrNameTooLong, l)
	}

	if kind != HMAC && (digits != 6 && digits != 8) {
		return ErrInvalidNumberOfDigits
	}

	if alg == HMACSHA512 {
		return fmt.Errorf("%w: This hash algorithm is not supported by the firmware", errors.ErrUnsupported)
	}

	secret = shortenKey(secret, alg)
	secret = padKey(secret)

	tvs := []tlv.TagValue{
		tlv.New(tagCredentialID, []byte(id)),
		tlv.New(tagKey, []byte{byte(alg) | byte(kind), byte(digits)}, secret),
		props.TagValue(true),
	}

	if counter > 0 && kind == HOTP {
		tvs = append(tvs, tlv.TagValue{
			Tag:   tagInitialCounter,
			Value: binary.BigEndian.AppendUint32(nil, counter),
		})
	}

	_, err := c.send(insPut, 0x00, 0x00, tvs...)
	return err
}

func shortenKey(key []byte, alg Algorithm) []byte {
	if h := alg.Hash()(); len(key) > h.BlockSize() {
		h.Write(key)
		return h.Sum(nil)
	}

	return key
}

func padKey(key []byte) []byte {
	keyLen := len(key)
	if keyLen >= HMACMinimumKeySize {
		return key
	}

	pad := make([]byte, HMACMinimumKeySize-keyLen)

	return append(pad, key...)
}
