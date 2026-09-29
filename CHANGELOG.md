# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `THROTTLE_LIMIT` and `THROTTLE_TTL`: requests allowed per route per IP, and the window in milliseconds. Default to 10 per 60 s.
- `SIWE_DOMAIN`: comma-separated list of UI hosts (with port) allowed in SIWE messages. Required in production; defaults to `localhost` and `localhost:3000` elsewhere.
- `CHEST_PATH`: location of the chest file. Defaults to `<cwd>/chest.json`; `docker-compose.yml` sets it to `/app/data/chest.json` on the `wulong-data` volume.
- `CHEST_MAX_BYTES`: maximum size of the chest file. Defaults to 50 MB; a store that would exceed it returns 507 and leaves the chest untouched.
- [`docs/KEY_DERIVATION.md`](docs/KEY_DERIVATION.md): design for deriving the ML-KEM key pair, an identity key and a relayer wallet inside the enclave from the dstack KMS, so that no private key is ever passed through env or stored. Covers attestation binding, verification, on-chain upgrade governance and the remaining trust assumptions.
- `DSTACK_SIMULATOR_ENDPOINT`: dstack simulator socket path or URL, from which keys are derived in development. Forbidden in production.
- `GET /chest/attestation?nonce=`: an optional 32-byte hex client nonce, placed in the second half of the quote's `report_data` so replayed quotes are detected.
- `GET /chest/attestation` returns `identityPublicKey`, `reportData`, the EIP-712 `keyManifest` signed at boot by the identity key, and the identity key's `identitySignatureChain`.
- `pnpm verify:attestation` checks the key binding: it sends a random nonce, recomputes `report_data`, compares it with the quote, and checks the manifest signer and ML-KEM hash.

### Fixed

- `POST /chest/store` required no authentication, so anyone could write to `chest.json` for any address. It now requires SIWE, and the caller must be one of `publicAddresses` (403 otherwise).
- Rate limiting now applies to every route: `ThrottlerGuard` was configured but never registered.
- Pending SIWE nonces are capped at 10,000; past the cap, `POST /auth/nonce` returns 429 instead of growing memory without bound.
- In production, the client IP is read from `X-Forwarded-For` (one proxy hop trusted), so clients behind Phala's proxy are not throttled together.
- Concurrent `POST /chest/store` calls could overwrite each other and lose secrets. Writes to the chest are now serialized.
- A crash mid-write could corrupt the whole chest. It is now written to a flushed temp file and renamed into place.
- Every redeploy wiped all stored secrets, since the chest lived in the container filesystem. It now lives on a named Docker volume.
- The ML-KEM private key was generated off-box and passed through env, so whoever generated it or could read the deployment env could decrypt every secret. It is now derived at boot inside the enclave from the dstack KMS (v1 `GetKey`), along with an identity key, and never stored or exported. See [`docs/KEY_DERIVATION.md`](docs/KEY_DERIVATION.md).
- In production, startup now fails if `ADMIN_MLKEM_*`, any `*PRIVATE_KEY`, `*MNEMONIC` or `*SEED` variable, or `DSTACK_SIMULATOR_ENDPOINT` is set, or if keys cannot be derived.
- Setting `ADMIN_MLKEM_PUBLIC_KEY` no longer skips loading secrets from `KMS_URL`.
- The attestation's `report_data` was only a timestamp, so anyone between the client and the enclave could replace `mlkemPublicKey` with their own key while serving a genuine quote. It now commits to the ML-KEM and identity public keys, as specified in [`docs/KEY_DERIVATION.md`](docs/KEY_DERIVATION.md#report_data).

### Changed

- **Breaking:** `POST /chest/store` requires the `x-siwe-message` and `x-siwe-signature` headers. Nonces are single-use, so storing and then accessing takes two sign-ins.
- **Breaking:** `POST /auth/nonce` takes a JSON body `{ "address": "0x…" }`, and the nonce is only accepted in a message signed by that address.
- **Breaking:** the server's ML-KEM key changes, and secrets stored under the old env key can no longer be decrypted by the server. No migration is provided.
- **Breaking:** requires a dstack ≥ 0.6.0 guest agent (`/v1/GetKey`). Development needs the dstack simulator.
- **Breaking:** `GET /chest/attestation` returns 503 when the keys have not been derived, instead of a quote without a key. Its `report_data` layout changes, so clients must check the new binding.

- Bump NestJS to 12, including `@nestjs/config` 12 and `@nestjs/swagger` 12.
- Bump TypeScript to 6.0 and `@types/node` to 26. TypeScript 7 is held back until `typescript-eslint`, `ts-jest` and `@nestjs/swagger` support it.
- Bump all other dependencies to their latest minor and patch versions.
- Run Jest with `--experimental-vm-modules` so it can load the ESM-only NestJS 12 packages.
- Require Node.js 24 in CI and in the Docker images.
- Set `rootDir`, `types` and `strict` explicitly in `tsconfig.json` and drop the deprecated `baseUrl`, keeping the TypeScript 5 behavior.
- Ignore `NOTES.md` and `notes/`.
- Remove the codecov badge and the w3hc image from the README.
- Remove the Codecov upload from CI, along with the coverage run that fed it.

### Fixed

- SIWE verification now enforces the message domain, the server-issued nonce, `Issued At`, `Expiration Time` and `Not Before`, and requires the `https` scheme in production. A nonce is consumed by any verification attempt, including a failed one ([#23](https://github.com/w3hc/wulong/issues/23)).
