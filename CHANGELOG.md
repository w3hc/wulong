# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `SIWE_DOMAIN`: comma-separated list of UI hosts (with port) allowed in SIWE messages. Required in production; defaults to `localhost` and `localhost:3000` elsewhere.

### Changed

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
