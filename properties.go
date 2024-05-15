package secrets

import (
	"strings"

	"cunicu.li/go-iso7816/encoding/tlv"
)

type Properties byte

const (
	TouchRequired Properties = 0x01
	PINEncrypted  Properties = 0x02
	PWSDataExists
)

func (p Properties) String() string {
	strs := []string{}

	if p&PINEncrypted != 0 {
		strs = append(strs, "pin-encrypted")
	}

	if p&PWSDataExists != 0 {
		strs = append(strs, "password-safe")
	}

	if p&TouchRequired != 0 {
		strs = append(strs, "touch-required")
	}

	return strings.Join(strs, ", ")
}

func (p Properties) TagValue(skipLength bool) tlv.TagValue {
	var q byte

	if p&TouchRequired != 0 {
		q |= 0x02
	}

	if p&PINEncrypted != 0 {
		q |= 0x04
	}

	return tlv.TagValue{
		Tag:        tagProperties,
		Value:      []byte{q},
		SkipLength: skipLength,
	}
}
