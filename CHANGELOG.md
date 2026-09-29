# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `THROTTLE_LIMIT` and `THROTTLE_TTL`: requests allowed per route per IP, and the window in milliseconds. Default to 10 per 60 s.
- `SIWE_DOMAIN`: comma-separated list of UI hosts (with port) allowed in SIWE messages. Required in production; defaults to `localhost` and `localhost:3000` elsewhere.

### Fixed

- `POST /chest/store` required no authentication, so anyone could write to `chest.json` for any address. It now requires SIWE, and the caller must be one of `publicAddresses` (403 otherwise).
- Rate limiting now applies to every route: `ThrottlerGuard` was configured but never registered.
- Pending SIWE nonces are capped at 10,000; past the cap, `POST /auth/nonce` returns 429 instead of growing memory without bound.
- In production, the client IP is read from `X-Forwarded-For` (one proxy hop trusted), so clients behind Phala's proxy are not throttled together.

### Changed

- **Breaking:** `POST /chest/store` requires the `x-siwe-message` and `x-siwe-signature` headers. Nonces are single-use, so storing and then accessing takes two sign-ins.
- **Breaking:** `POST /auth/nonce` takes a JSON body `{ "address": "0x…" }`, and the nonce is only accepted in a message signed by that address.

- Bump NestJS to 12, including `@nestjs/config` 12 and `@nestjs/swagger` 12.
- Bump TypeScript to 6.0 and `@types/node` to 26. TypeScript 7 is held back until `typescript-eslint`, `ts-jest` and `@nestjs/swagger` support it.
- Bump all other dependencies to their latest minor and patch versions.
- Run Jest with `--experimental-vm-modules` so it can load the ESM-only NestJS 12 packages.
- Require Node.js 24 in CI and in the Docker images.
- Set `rootDir`, `types` and `strict` explicitly in `tsconfig.json` and drop the deprecated `baseUrl`, keeping the TypeScript 5 behavior.
- Ignore `NOTES.md` and `notes/`.
- Remove the codecov badge and the w3hc image from the README.

### Fixed

- SIWE verification now enforces the message domain, the server-issued nonce, `Issued At`, `Expiration Time` and `Not Before`, and requires the `https` scheme in production. A nonce is consumed by any verification attempt, including a failed one ([#23](https://github.com/w3hc/wulong/issues/23)).
