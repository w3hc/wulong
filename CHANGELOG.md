# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `CORS_ORIGINS`: comma-separated origins of the browser UIs allowed to call the API. Unset allows none; startup fails on an entry that is not an exact origin ([#41](https://github.com/w3hc/wulong/issues/41)).

### Fixed

- CORS combined `origin: '*'` with `credentials: true` in development, which browsers reject, and was disabled in production. Auth uses SIWE headers, not cookies, so credentials mode is gone and origins come from `CORS_ORIGINS` ([#41](https://github.com/w3hc/wulong/issues/41)).
- `GET /chest/access/:slot` returned plaintext without cache headers. It now sends `Cache-Control: no-store` and `Pragma: no-cache` ([#41](https://github.com/w3hc/wulong/issues/41)).
- `X-Forwarded-For` handling is tested: ignored when TLS terminates in the enclave, and only the proxy's own hop trusted under `ALLOW_TLS_OUTSIDE_ENCLAVE` ([#41](https://github.com/w3hc/wulong/issues/41)).

- `docker-compose.yml` ran `julienberanger/wulong:latest`, a mutable tag. It now pins the v0.2.0 image, `ghcr.io/w3hc/wulong@sha256:fdbd5ffa…`, so the attested compose hash commits to the image ([#40](https://github.com/w3hc/wulong/issues/40)).
- A tag pushed twice ran two releases concurrently and added the image digest to the release notes twice. The docs link in those notes was relative and did not resolve.

## [0.2.0] - 2026-09-29

### Added

- `THROTTLE_LIMIT` and `THROTTLE_TTL`: requests allowed per route per IP, and the window in milliseconds. Default to 10 per 60 s.
- `SIWE_DOMAIN`: comma-separated list of UI hosts (with port) allowed in SIWE messages. Required in production; defaults to `localhost` and `localhost:3000` elsewhere.
- `CHEST_PATH`: location of the chest file. Defaults to `<cwd>/chest.json`; `docker-compose.yml` sets it to `/app/data/chest.json` on the `wulong-data` volume.
- `CHEST_MAX_BYTES`: maximum size of the chest file. Defaults to 50 MB; a store that would exceed it returns 507 and leaves the chest untouched.
- [`docs/KEY_DERIVATION.md`](docs/KEY_DERIVATION.md): design for deriving the ML-KEM key pair, an identity key and a relayer wallet inside the enclave from the dstack KMS, so that no private key is ever passed through env or stored. Covers attestation binding, verification, on-chain upgrade governance and the remaining trust assumptions.
- `DSTACK_SIMULATOR_ENDPOINT`: dstack simulator socket path or URL, from which keys are derived in development. Forbidden in production.
- `GET /chest/attestation?nonce=`: an optional 32-byte hex client nonce, placed in the second half of the quote's `report_data` so replayed quotes are detected.
- `GET /chest/attestation` returns `identityPublicKey`, `reportData`, the EIP-712 `keyManifest` signed at boot by the identity key, and the identity key's `identitySignatureChain`.
- `TLS_ALT_NAMES`: gateway hostnames the in-enclave TLS certificate is issued for, e.g. `<app-id>-3000s.<gateway-domain>`. Required in production.
- `ALLOW_TLS_OUTSIDE_ENCLAVE`: serves plain HTTP behind a TLS-terminating proxy. Logged as an error at boot and every minute; not passed through by `docker-compose.yml`, so opting out changes the compose hash.
- `GET /chest/attestation` returns `tlsCertificate`, the leaf certificate served from inside the enclave, and `report_data` commits to it.
- `pnpm verify:attestation` checks that the certificate of its TLS session is the one bound by the attestation.
- `pnpm verify:attestation` checks the key binding: it sends a random nonce, recomputes `report_data`, compares it with the quote, and checks the manifest signer and ML-KEM hash.
- `GET /chest/attestation` returns `measurements` (MRTD, RTMR0–3) and the dstack `eventLog`. RTMR3 identifies the app; [`docs/TEE_SETUP.md`](docs/TEE_SETUP.md#measurements) explains how to reproduce it from the compose file.
- `pnpm verify:attestation` checks that the returned measurements are the ones in the quote.
- [`release.yml`](.github/workflows/release.yml): on a `v*` tag, CI builds the image, pushes it to `ghcr.io/w3hc/wulong`, attests its build provenance and publishes its digest in the release notes. [`docs/DOCKER.md`](docs/DOCKER.md#releases) explains release → digest → compose hash and how to rebuild and compare a digest.
- CI checks formatting, lints without `--fix`, runs `pnpm build` and `pnpm audit --prod`, and builds the image twice to check that its digest reproduces.
- `pnpm format:check` and `pnpm lint:fix`.

### Fixed

- `POST /chest/store` required no authentication, so anyone could write to `chest.json` for any address. It now requires SIWE, and the caller must be one of `publicAddresses` (403 otherwise).
- Rate limiting now applies to every route: `ThrottlerGuard` was configured but never registered.
- Pending SIWE nonces are capped at 10,000; past the cap, `POST /auth/nonce` returns 429 instead of growing memory without bound.
- Under `ALLOW_TLS_OUTSIDE_ENCLAVE`, the client IP is read from `X-Forwarded-For` (one proxy hop trusted), so clients behind Phala's proxy are not throttled together. With TLS in the enclave the gateway cannot set it, and all clients share one counter.
- Concurrent `POST /chest/store` calls could overwrite each other and lose secrets. Writes to the chest are now serialized.
- A crash mid-write could corrupt the whole chest. It is now written to a flushed temp file and renamed into place.
- Every redeploy wiped all stored secrets, since the chest lived in the container filesystem. It now lives on a named Docker volume.
- The ML-KEM private key was generated off-box and passed through env, so whoever generated it or could read the deployment env could decrypt every secret. It is now derived at boot inside the enclave from the dstack KMS (v1 `GetKey`), along with an identity key, and never stored or exported. See [`docs/KEY_DERIVATION.md`](docs/KEY_DERIVATION.md).
- TLS terminated at Phala's proxy, outside the enclave, so every secret returned by `GET /chest/access` crossed it in plaintext. TLS now terminates inside the enclave with a key and certificate from the dstack KMS (`GetTlsKey`), the gateway runs in passthrough mode (`-3000s` URLs), and production refuses to start without it. See [`docs/PHALA_CONFIG.md`](docs/PHALA_CONFIG.md#endpoint-url-format).
- `pnpm build` failed on a value import of `SignedKeyManifest` in a decorated DTO.
- In production, startup now fails if `ADMIN_MLKEM_*`, any `*PRIVATE_KEY`, `*MNEMONIC` or `*SEED` variable, or `DSTACK_SIMULATOR_ENDPOINT` is set, or if keys cannot be derived.
- Setting `ADMIN_MLKEM_PUBLIC_KEY` no longer skips loading secrets from `KMS_URL`.
- The attestation's `report_data` was only a timestamp, so anyone between the client and the enclave could replace `mlkemPublicKey` with their own key while serving a genuine quote. It now commits to the ML-KEM and identity public keys, as specified in [`docs/KEY_DERIVATION.md`](docs/KEY_DERIVATION.md#report_data).
- A deployment outside a TEE started normally in production and served mock attestations; the SEV-SNP, native TDX and Nitro paths were stubs, the Nitro one reporting a made-up document as `aws-nitro`. Only dstack remains, and production refuses to start without `/var/run/dstack.sock`, with `DSTACK_SIMULATOR_ENDPOINT`, or if the first quote fails or does not carry the requested `report_data`.
- The attestation's `measurement` was read at offset 112 of the quote, which holds MRSIGNERSEAM, not MRTD (at 184).
- `TeePlatformService` was provided twice, in `AppModule` and `SecretModule`. It now lives in `AttestationModule`.
- `pnpm audit --prod` reported one high and three moderate findings, from `@phala/dstack-sdk`'s viem and Solana dependencies. The SDK is removed: quotes go through Wulong's own dstack client (`/GetQuote`).
- `docker-compose.yml` ran `julienberanger/wulong:latest` with `pull_policy: always`, so whoever controlled the registry account could ship different code under the same attested compose hash. The image is now pinned by digest and built in CI.
- The runtime image ran as root and had pnpm installed globally. It now runs as `node` on a digest-pinned Node 24 base, with only `dist` and production dependencies.
- `.dockerignore` let `secrets/`, `chest.json`, `.env.*` and `notes/` into the build context.
- CI never ran `pnpm build`, so a compile error in `main.ts` could ship green.

### Changed

- **Breaking:** `POST /chest/store` requires the `x-siwe-message` and `x-siwe-signature` headers. Nonces are single-use, so storing and then accessing takes two sign-ins.
- **Breaking:** `POST /auth/nonce` takes a JSON body `{ "address": "0x…" }`, and the nonce is only accepted in a message signed by that address.
- **Breaking:** the server's ML-KEM key changes, and secrets stored under the old env key can no longer be decrypted by the server. No migration is provided.
- **Breaking:** requires a dstack ≥ 0.6.0 guest agent (`/v1/GetKey`). Development needs the dstack simulator.
- **Breaking:** `GET /chest/attestation` returns 503 when the keys have not been derived, instead of a quote without a key. Its `report_data` layout changes, so clients must check the new binding.
- **Breaking:** `GET /attestation` is removed; use `GET /chest/attestation`, which binds the keys.
- **Breaking:** `GET /chest/attestation` replaces `measurement` with `measurements` and `eventLog`, drops `publicKey`, and `platform` is `intel-tdx`, or `none` outside production without dstack.
- **Breaking:** the image moves to `ghcr.io/w3hc/wulong` and runs as `node`. An existing `wulong-data` volume must be handed to uid 1000 once, see [`docs/DOCKER.md`](docs/DOCKER.md#upgrading-from-a-root-image).
- **Breaking:** `pnpm lint` no longer fixes; use `pnpm lint:fix`.

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
