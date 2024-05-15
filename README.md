<!--
SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
SPDX-License-Identifier: Apache-2.0
-->

# go-trussed-secrets

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cunicu/go-trussed-secrets/test.yaml?style=flat-square)](https://github.com/cunicu/go-trussed-secrets/actions)
[![goreportcard](https://goreportcard.com/badge/github.com/cunicu/go-trussed-secrets?style=flat-square)](https://goreportcard.com/report/github.com/cunicu/go-trussed-secrets)
[![Codecov branch](https://img.shields.io/codecov/c/github/cunicu/go-trussed-secrets/main?style=flat-square&token=6XoWouQg6K)](https://app.codecov.io/gh/cunicu/go-trussed-secrets/tree/main)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/cunicu/go-trussed-secrets/blob/main/LICENSES/Apache-2.0.txt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/cunicu/go-trussed-secrets?style=flat-square)
[![Go Reference](https://pkg.go.dev/badge/github.com/cunicu/go-trussed-secrets.svg)](https://pkg.go.dev/github.com/cunicu/go-trussed-secrets)

The package `go-trussed-secrets` implements the protocol of the [_Trussed Secrets App_](https://github.com/Nitrokey/trussed-secrets-app).
It is used by the Nitrokey 3 tokens to provide HOTP, TOTP, reverse HOTP and challenge/response credentials.

**Note:** This package uses the CCID smart-card interface rather than the [CTAPHID](https://github.com/Nitrokey/trussed-secrets-app/blob/main/docs/ctaphid.md) interface as used by [pynitrokey](https://github.com/Nitrokey/pynitrokey)

## Features

- Calculation of
  - Time-based One-time Passwords (TOTP)
  - Hash-based One-time Passwords (HOTP)
  - Reverse Hash-based One-time Passwords (HOTP)
  - Static password safe entries
- PIN based authentication
- Factory reset of applet
- Credential management
  - Add
  - Get
  - List
  - Remove
  - Update
  - Rename

### Unimplemented

The following features have not been implemented as they have been deprecated in [Nitrokey/trussed-secrets-app](https://github.com/Nitrokey/trussed-secrets-app):

- [YubiKey challenge/response slots](https://docs.yubico.com/yesdk/users-manual/application-otp/challenge-response.html) (as used by KeePassXC)
  - Also includes challenge/response-based PIN authentication
- `CalculateAll` instruction
  - Is disabled by default on Nitrokey 3's

## Roadmap

- [Untruncated responses](https://github.com/Nitrokey/trussed-secrets-app/issues/116)
- [CTAPHID interface](https://github.com/Nitrokey/trussed-secrets-app/blob/main/docs/ctaphid.md)

## Tested devices

- Nitrokey 3
  - FW version v1.7.0

## References

- [**RFC 4226:** HOTP: An HMAC-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc4226)
- [**RFC 6238:** TOTP: Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
- [CTAPHID Protocol specification](https://github.com/Nitrokey/trussed-secrets-app/blob/main/docs/ctaphid.md)
- Token App: [Nitrokey/trussed-secrets-app](https://github.com/Nitrokey/trussed-secrets-app)
- Client CLI: [Nitrokey/pynitrokey (`pynitrokey/nk3/secrets_app.py`)](https://github.com/Nitrokey/pynitrokey/blob/master/pynitrokey/nk3/secrets_app.py)

## Authors

- Steffen Vogel ([@stv0g](https://github.com/stv0g))

## License

go-trussed-secrets is licensed under the [Apache 2.0](./LICENSE) license.
