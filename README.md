# Wulong

[![NestJS](https://img.shields.io/badge/NestJS-v11-E0234E?logo=nestjs)](https://nestjs.com/)
[![Test](https://github.com/julienbrg/wulong/actions/workflows/test.yml/badge.svg)](https://github.com/julienbrg/wulong/actions/workflows/test.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![pnpm](https://img.shields.io/badge/pnpm-10.23-F69220?logo=pnpm)](https://pnpm.io/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=node.js)](https://nodejs.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A NestJS API designed to run inside a Trusted Execution Environment (TEE) with quantum-resistant ML-KEM-1024 encryption and Web3 authentication (SIWE), giving users cryptographic guarantees that the operator cannot access their data during processing. Optimized for [Phala Network](https://phala.network/) deployment.

## Features

- **TEE Attestation** - Cryptographic proof of code integrity
  - Platforms: [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html), [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html), [AWS Nitro](https://aws.amazon.com/ec2/nitro/), [Phala](https://phala.network/)
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

# Generate ML-KEM keypair
pnpm ts-node scripts/generate-admin-keypair.ts
# Copy the output keys to your .env file

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
# Build and push Docker image
docker buildx build --platform linux/amd64 -t YOUR_USERNAME/wulong:latest --push .

# Deploy to Phala Cloud
phala deploy --interactive

# Test against Phala deployment
WULONG_URL=https://your-app-id-3000.phala.network pnpm test:store-access
```

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
- [**TEE Setup**](docs/TEE_SETUP.md) - Platform-specific deployment (AMD SEV-SNP, Intel TDX, AWS Nitro, Phala)
- [**Side Channel Attacks**](docs/SIDE_CHANNEL_ATTACKS.md) - Security considerations and mitigations
- [**Implementation Plan**](docs/MLKEM_IMPLEMENTATION_PLAN.md) - ML-KEM development roadmap

## License

GPL-3.0

## Contact

**Julien Béranger** ([GitHub](https://github.com/julienbrg))

- Element: [@julienbrg:matrix.org](https://matrix.to/#/@julienbrg:matrix.org)
- Farcaster: [julien-](https://warpcast.com/julien-)
- Telegram: [@julienbrg](https://t.me/julienbrg)
