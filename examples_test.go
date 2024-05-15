// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !ci

package secrets_test

import (
	"fmt"
	"log"
	"time"

	"cunicu.li/go-iso7816/drivers/pcsc"
	"cunicu.li/go-iso7816/filter"
	"github.com/ebfe/scard"

	secrets "cunicu.li/go-trussed-secrets"
)

func Example() {
	ctx, err := scard.EstablishContext()
	if err != nil {
		log.Printf("Failed to establish context: %v", err)
		return
	}

	sc, err := pcsc.OpenFirstCard(ctx, filter.IsNitrokey3, false)
	if err != nil {
		log.Printf("Failed to connect to card: %v", err)
		return
	}

	c, err := secrets.NewCard(sc)
	if err != nil {
		log.Print(err)
		return
	}

	defer c.Close()

	// Fix the clock
	c.Clock = func() time.Time {
		return time.Unix(59, 0)
	}

	// Select the Trussed Secrets applet
	if _, err = c.Select(); err != nil {
		log.Printf("Failed to select applet: %v", err)
		return
	}

	// Reset the applet
	if err := c.Reset(); err != nil {
		log.Printf("Failed to reset applet: %v", err)
		return
	}

	// Add the testvector
	if err = c.PutOTP("testvector", secrets.HMACSHA1, secrets.TOTP, 8, []byte("12345678901234567890"), 0, 0); err != nil {
		log.Printf("Failed to put: %v", err)
		return
	}

	names, err := c.List()
	if err != nil {
		log.Printf("Failed to list: %v", err)
		return
	}

	for _, name := range names {
		fmt.Printf("Name: %s\n", name)
	}

	otp, _ := c.Calculate("testvector")
	fmt.Printf("OTP: %s\n", otp.OTP())

	// Output:
	// Name: testvector (HMAC-SHA1, TOTP)
	// OTP: 94287082
}
