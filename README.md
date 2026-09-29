# Wulong

[![NestJS](https://img.shields.io/badge/NestJS-v11-E0234E?logo=nestjs)](https://nestjs.com/)
[![Test](https://github.com/julienbrg/wulong/actions/workflows/test.yml/badge.svg)](https://github.com/julienbrg/wulong/actions/workflows/test.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![pnpm](https://img.shields.io/badge/pnpm-10.23-F69220?logo=pnpm)](https://pnpm.io/)
[![Node.js](https://img.shields.io/badge/Node.js-24-339933?logo=node.js)](https://nodejs.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A NestJS API designed to run inside a Trusted Execution Environment (TEE) with quantum-resistant ML-KEM-1024 encryption and Web3 authentication (SIWE), giving users cryptographic guarantees that the operator cannot access their data during processing. Optimized for [Phala Network](https://phala.network/) deployment.

## Features

- **TEE Attestation** - Cryptographic proof of code integrity
  - Platform: [dstack](https://github.com/Dstack-TEE/dstack) on [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html), e.g. [Phala Cloud](https://phala.network/); refuses to start in production outside it
  - See [TEE setup guide](docs/TEE_SETUP.md)
- **Web3 Authentication** - [SIWE](https://login.xyz) (Sign-In with Ethereum)
  - See [auth guide](docs/SIWE.md)
- **Quantum-Resistant Encryption** - [ML-KEM-1024](https://csrc.nist.gov/pubs/fips/203/final) (NIST FIPS 203) with multi-recipient support
  - Client-side encryption with [w3pk](https://github.com/w3hc/w3pk)
  - Privacy-first: clients can decrypt locally without server
  - Server-side decryption for operations (with SIWE auth)
  - See [ML-KEM guide](docs/MLKEM.md) and [client guide](docs/CLIENT_ENCRYPTION.md)

## Quick Start

### Local Development (without Docker)

Mock TEE attestation - no real hardware security.

```bash
# Install dependencies
pnpm install

# Setup environment
cp .env.template .env

# Generate TLS certificates
mkdir -p secrets
openssl req -x509 -newkey rsa:4096 -keyout secrets/tls.key -out secrets/tls.cert -days 365 -nodes -subj "/CN=localhost"

# Run the dstack simulator (keys are derived from it, never set in .env)
# git clone https://github.com/Dstack-TEE/dstack && cd dstack/sdk/simulator
# ./build.sh && ./dstack-simulator
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090

# Start development server
pnpm start:dev

# Test ML-KEM encryption (in another terminal)
pnpm test:mlkem              # Basic encryption test
pnpm test:store-access       # Full store+access flow with SIWE
```

Access at `https://localhost:3000` (accept self-signed certificate warning)

### Docker Development

Mock TEE attestation - no real hardware security.

```bash
docker compose -f docker-compose.dev.yml up
```

Access at `https://localhost:3000`

### Phala Cloud (Production TEE)

```bash
# Tag a release: CI builds, pushes and attests the image, and publishes its digest
# in the release notes. Pin that digest in docker-compose.yml (see docs/DOCKER.md#releases)
git tag v0.2.0 && git push origin v0.2.0

# Deploy to Phala Cloud
phala deploy --interactive

# Verify the attestation, including that TLS terminates in the enclave
pnpm verify:attestation https://your-app-id-3000s.phala.network/chest/attestation

# Test against Phala deployment. The certificate comes from the dstack KMS CA,
# not a public CA: skip the trust store only once verify:attestation passes
NODE_TLS_REJECT_UNAUTHORIZED=0 WULONG_URL=https://your-app-id-3000s.phala.network pnpm test:store-access
```

## Rate Limiting

Every route is rate-limited per client IP, and each route has its own counter:

| Limit | Default | Env var |
| --- | --- | --- |
| Requests per route per IP | 10 | `THROTTLE_LIMIT` |
| Window | 60 s | `THROTTLE_TTL` (ms) |
| Pending SIWE nonces | 10,000 | — |

Past a limit, the API answers `429 Too Many Requests`. Once 10,000 nonces are pending, `POST /auth/nonce` is rejected until some are used or expire (5 minutes); live nonces are never evicted. With TLS terminating in the enclave, the gateway forwards encrypted bytes and cannot add `X-Forwarded-For`, so the client IP is the gateway's and every client shares one counter. `X-Forwarded-For` is trusted only under the `ALLOW_TLS_OUTSIDE_ENCLAVE` opt-out.

## Storage

Secrets are stored, encrypted, in a single JSON file. Writes are serialized within the process and saved atomically (temp file, then rename).

| Setting | Default | Env var |
| --- | --- | --- |
| Chest file | `<cwd>/chest.json` | `CHEST_PATH` |
| Maximum chest size | 50 MB | `CHEST_MAX_BYTES` (bytes) |

`docker-compose.yml` keeps the chest at `/app/data/chest.json` on the `wulong-data` named volume, so it survives redeploys. A store that would push the chest past the cap is rejected with `507 Insufficient Storage`. The lock is per process: run a single replica.

## Docs

### Setup & Deployment

- [**Local Setup**](docs/LOCAL_SETUP.md) - Run locally without Docker (development)
- [**Docker Setup**](docs/DOCKER.md) - Run with Docker (development & testing)
- [**Phala Deployment**](docs/PHALA_CONFIG.md) - Deploy to Phala Cloud TEE (production)

### API & Usage

- [**API Reference**](docs/API_REFERENCE.md) - Complete REST API endpoint documentation
- [**ML-KEM Encryption**](docs/MLKEM.md) - Quantum-resistant encryption guide
- [**Client-Side Encryption**](docs/CLIENT_ENCRYPTION.md) - How to encrypt data with w3pk
- [**SIWE Authentication**](docs/SIWE.md) - Ethereum wallet authentication guide
- [**Testing Guide**](docs/MLKEM_TESTING_GUIDE.md) - Local and Phala testing procedures

### Architecture & Security

- [**Overview**](docs/OVERVIEW.md) - Project overview, architecture, and security model
- [**TEE Setup**](docs/TEE_SETUP.md) - dstack attestation, fail-closed startup, and how to reproduce the measurements
- [**Side Channel Attacks**](docs/SIDE_CHANNEL_ATTACKS.md) - Security considerations and mitigations
- [**Implementation Plan**](docs/MLKEM_IMPLEMENTATION_PLAN.md) - ML-KEM development roadmap

## License

GPL-3.0

## Contact

**Julien Béranger** ([GitHub](https://github.com/julienbrg))

- Element: [@julienbrg:matrix.org](https://matrix.to/#/@julienbrg:matrix.org)
- Farcaster: [julien-](https://warpcast.com/julien-)
- Telegram: [@julienbrg](https://t.me/julienbrg)
