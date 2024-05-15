// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"encoding/hex"
	"time"

	secrets "cunicu.li/go-trussed-secrets"
)

type vector struct {
	ID         string
	Algorithm  secrets.Algorithm
	Kind       secrets.Kind
	Properties secrets.Properties
	Digits     int
	Secret     []byte
	Time       time.Time
	Counter    uint32
	Code       string
	Hash       []byte
}

func fromString(s string) []byte {
	return []byte(s)
}

func fromHex(s string) []byte {
	h, err := hex.DecodeString(s)
	if err != nil {
		panic("failed to parse hex: " + err.Error())
	}
	return h
}

// nolint: gochecknoglobals
var (
	// See: RFC Errata for RFC 6238 (https://www.rfc-editor.org/errata/eid2866)
	testSecretSHA1   = fromString("12345678901234567890")
	testSecretSHA256 = fromString("12345678901234567890123456789012")
	testSecretSHA512 = fromString("1234567890123456789012345678901234567890123456789012345678901234")

	vectorsMix = []vector{
		{ID: "mix-test-01", Algorithm: secrets.HMACSHA1, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA1, Properties: secrets.TouchRequired},
		{ID: "mix-test-02", Algorithm: secrets.HMACSHA256, Kind: secrets.HOTP, Digits: 8, Secret: testSecretSHA256},
		{ID: "mix-test-03", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTPReverse, Digits: 8, Secret: testSecretSHA1},
		{ID: "mix-test-04", Algorithm: secrets.HMACSHA1, Kind: secrets.HMAC, Digits: 6, Secret: testSecretSHA1},
	}

	// RFC 6238 Appendix B - Test Vectors
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
	// TODO: SHA512 is not supported by firmware yet (as of 1.7.0)
	vectorsTOTP = []vector{
		{ID: "rfc6238-test-01", Algorithm: secrets.HMACSHA1, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(59, 0), Code: "94287082"},
		{ID: "rfc6238-test-02", Algorithm: secrets.HMACSHA256, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(59, 0), Code: "46119246"},
		// {Name: "rfc6238-test-03", Alg: app.HmacSha512, Typ: app.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(59, 0), Code: "90693936"},
		{ID: "rfc6238-test-04", Algorithm: secrets.HMACSHA1, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(1111111109, 0), Code: "07081804"},
		{ID: "rfc6238-test-05", Algorithm: secrets.HMACSHA256, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(1111111109, 0), Code: "68084774"},
		// {Name: "rfc6238-test-06", Alg: app.HmacSha512, Typ: app.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(1111111109, 0), Code: "25091201"},
		{ID: "rfc6238-test-07", Algorithm: secrets.HMACSHA1, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(1111111111, 0), Code: "14050471"},
		{ID: "rfc6238-test-08", Algorithm: secrets.HMACSHA256, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(1111111111, 0), Code: "67062674"},
		// {Name: "rfc6238-test-09", Alg: app.HmacSha512, Typ: app.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(1111111111, 0), Code: "99943326"},
		{ID: "rfc6238-test-10", Algorithm: secrets.HMACSHA1, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(1234567890, 0), Code: "89005924"},
		{ID: "rfc6238-test-11", Algorithm: secrets.HMACSHA256, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(1234567890, 0), Code: "91819424"},
		// {Name: "rfc6238-test-12", Alg: app.HmacSha512, Typ: app.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(1234567890, 0), Code: "93441116"},
		{ID: "rfc6238-test-13", Algorithm: secrets.HMACSHA1, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(2000000000, 0), Code: "69279037"},
		{ID: "rfc6238-test-14", Algorithm: secrets.HMACSHA256, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(2000000000, 0), Code: "90698825"},
		// {Name: "rfc6238-test-15", Alg: app.HmacSha512, Typ: app.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(2000000000, 0), Code: "38618901"},
		{ID: "rfc6238-test-16", Algorithm: secrets.HMACSHA1, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(20000000000, 0), Code: "65353130"},
		{ID: "rfc6238-test-17", Algorithm: secrets.HMACSHA256, Kind: secrets.TOTP, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(20000000000, 0), Code: "77737706"},
		// {Name: "rfc6238-test-18", Alg: app.HmacSha512, Typ: app.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(20000000000, 0), Code: "47863826"},
	}

	// RFC 4226 Appendix D - HOTP Algorithm: Test Values
	//
	// See: https://datatracker.ietf.org/doc/html/rfc4226#page-32
	vectorsHOTP = []vector{
		{ID: "rfc4226-test-00", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 0, Code: "755224", Hash: fromHex("cc93cf18508d94934c64b65d8ba7667fb7cde4b0")},
		{ID: "rfc4226-test-01", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 1, Code: "287082", Hash: fromHex("75a48a19d4cbe100644e8ac1397eea747a2d33ab")},
		{ID: "rfc4226-test-02", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 2, Code: "359152", Hash: fromHex("0bacb7fa082fef30782211938bc1c5e70416ff44")},
		{ID: "rfc4226-test-03", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 3, Code: "969429", Hash: fromHex("66c28227d03a2d5529262ff016a1e6ef76557ece")},
		{ID: "rfc4226-test-04", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 4, Code: "338314", Hash: fromHex("a904c900a64b35909874b33e61c5938a8e15ed1c")},
		{ID: "rfc4226-test-05", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 5, Code: "254676", Hash: fromHex("a37e783d7b7233c083d4f62926c7a25f238d0316")},
		{ID: "rfc4226-test-06", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 6, Code: "287922", Hash: fromHex("bc9cd28561042c83f219324d3c607256c03272ae")},
		{ID: "rfc4226-test-07", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 7, Code: "162583", Hash: fromHex("a4fb960c0bc06e1eabb804e5b397cdc4b45596fa")},
		{ID: "rfc4226-test-08", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 8, Code: "399871", Hash: fromHex("1b3c89f65e6c9e883012052823443f048b4332db")},
		{ID: "rfc4226-test-09", Algorithm: secrets.HMACSHA1, Kind: secrets.HOTP, Digits: 6, Secret: testSecretSHA1, Counter: 9, Code: "520489", Hash: fromHex("1637409809a679dc698207310c8c7fc07290d9e5")},
	}

	vectors = map[string][]vector{
		"TOTP": vectorsTOTP,
		"HOTP": vectorsHOTP,
	}
)
