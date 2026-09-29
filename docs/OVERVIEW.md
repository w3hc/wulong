# Wulong Overview

## Purpose

Wulong is a confidential computing API framework that provides cryptographic guarantees about data privacy during server-side processing. Built on NestJS, it enables developers to build APIs where even the infrastructure operator cannot access user data—a trust model verified through hardware attestation rather than organizational policy.

## Core Concepts

### Trusted Execution Environments (TEEs)

Wulong leverages hardware-based isolation provided by modern CPU security features. The application executes within a cryptographically sealed enclave where:

- **Memory isolation**: The host OS and operator cannot read enclave memory
- **Encrypted I/O**: TLS termination occurs inside the enclave, preventing plaintext exposure
- **Remote attestation**: Clients receive cryptographic proof of the exact code executing
- **Sealed secrets**: Cryptographic keys and sensitive configuration are only released after attestation verification

### Supported TEE Platforms

- **AMD SEV-SNP**: Secure Encrypted Virtualization with memory integrity
- **Intel TDX**: Trust Domain Extensions for VM-level isolation
- **AWS Nitro**: Amazon's proprietary enclave technology
- **Phala Network**: Decentralized TEE infrastructure on Intel TDX

### Architecture Philosophy

Wulong follows a **zero-trust operator model**. Traditional API security relies on trusting the infrastructure provider not to access data. Wulong inverts this: the operator is explicitly untrusted, and hardware isolation enforces confidentiality. Clients verify the running code through attestation before transmitting sensitive data.

## Security Model

### Threat Model

**Protected against:**
- Malicious host operator reading memory
- Network eavesdropping (TLS in enclave)
- Log-based data exfiltration
- Stack trace information leakage

**NOT protected against:**
- Side-channel attacks (timing, cache) - See [docs/SIDE_CHANNEL_ATTACKS.md](docs/SIDE_CHANNEL_ATTACKS.md) for mitigations
- Physical access to hardware
- Compromised TEE firmware
- Application logic bugs

### Trust Assumptions

**Trusted Components:**
1. TEE hardware vendor (AMD/Intel/AWS)
2. Application code (verifiable via attestation)
3. Key Management Service (KMS) attestation verification logic

**Explicitly Untrusted:**
- Host operating system
- Cloud provider operators
- Network infrastructure between client and enclave

## Key Features

### Attestation & Verification
The `/chest/attestation` endpoint exposes cryptographic evidence of the running code. Clients verify this evidence against known measurements before transmitting sensitive data. This creates a trustless verification model where code identity is proven mathematically rather than asserted. The attestation proves that:

1. **Code Integrity**: The exact code running in the TEE (via measurement/hash)
2. **TEE Authenticity**: The service is actually running in a genuine TEE
3. **No Privileged Access**: Even the operator cannot access user secrets

Users can request attestation at any time to verify the service does what it claims - it cannot access their data.

### Quantum-Resistant Encryption
ML-KEM-1024 (NIST FIPS 203) provides post-quantum cryptographic protection for client-side encryption. Clients encrypt secrets before transmission using the admin's public key exposed in attestation. The TEE decrypts with a private key that never leaves enclave memory. This ensures:

1. **Quantum resistance**: Protected against Shor's algorithm (breaks RSA/ECDSA)
2. **Admin-proof encryption**: Private key only in TEE memory, never on disk/logs
3. **Client verification**: ML-KEM public key comes with attestation proof
4. **End-to-end security**: Plaintext never leaves client until inside TEE

See [docs/CLIENT_ENCRYPTION.md](CLIENT_ENCRYPTION.md) for implementation guide.

### Web3 Authentication
Sign-In with Ethereum (SIWE) provides decentralized authentication without traditional credentials. Users prove identity through cryptographic signatures, eliminating password management and centralized identity providers. Owner-based access control ensures only authorized Ethereum addresses can retrieve secrets. See [docs/SIWE.md](docs/SIWE.md) for implementation details.

### Confidentiality Controls
- **Sanitized logging**: Structured log filtering prevents accidental data leakage
- **TLS-in-enclave**: Network plaintext never touches host infrastructure
- **KMS integration**: Secrets provisioned post-attestation, not at deploy time
- **Input validation**: Schema-based request validation prevents injection attacks
- **ML-KEM encryption**: Quantum-resistant client-side encryption with TEE-only decryption

### Operational Features
- Rate limiting and DoS protection
- Health check endpoints for orchestration systems
- Swagger/OpenAPI documentation generation
- Platform-agnostic TEE detection at runtime
- Keypair generation utilities for ML-KEM
- Comprehensive API reference documentation

## System Architecture

```
┌─────────────────────────────────────────────────┐
│                TEE Enclave Boundary             │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │       NestJS Application Layer          │   │
│  │  ┌──────────────┐  ┌─────────────────┐ │   │
│  │  │  Controllers │  │  Business Logic │ │   │
│  │  └──────────────┘  └─────────────────┘ │   │
│  └─────────────────────────────────────────┘   │
│                      ↓                          │
│  ┌─────────────────────────────────────────┐   │
│  │          Security Services              │   │
│  │  • Attestation Generation               │   │
│  │  • SIWE Authentication                  │   │
│  │  • TLS Termination                      │   │
│  │  • Secrets Management                   │   │
│  └─────────────────────────────────────────┘   │
│                      ↓                          │
│  ┌─────────────────────────────────────────┐   │
│  │         Hardware Isolation              │   │
│  │  • Encrypted Memory                     │   │
│  │  • Attestation Primitives               │   │
│  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
                       ↕ (encrypted channel)
              ┌────────────────────┐
              │   External KMS     │
              │ (attestation gate) │
              └────────────────────┘
```

### Data Flow

1. **Client Request**: TLS connection established directly with enclave
2. **Attestation**: Client verifies `/chest/attestation` endpoint before sending sensitive data
3. **Authentication**: SIWE signature validated against Ethereum address
4. **Processing**: Business logic executes within hardware-isolated memory
5. **Response**: Encrypted response sent through TLS tunnel

### Component Layers

**Application Layer**: Standard NestJS controllers and services, with TEE-awareness for attestation and secrets handling

**Security Layer**: Enforces confidentiality guarantees through sanitized logging, header-based authentication, and KMS integration

**Hardware Layer**: Platform-specific TEE implementations (SEV-SNP, TDX, Nitro) provide memory encryption and attestation

## Use Cases

### Private Data APIs
APIs processing personal data (health records, financial information) where regulatory compliance requires operator-proof confidentiality. Attestation provides auditable evidence of data handling.

### Web3 Oracles
Trusted computation for blockchain applications requiring off-chain data or complex calculations. TEEs prevent oracle manipulation by infrastructure providers.

### Multi-party Computation
Neutral computation zones where multiple parties contribute data but no single party (including the operator) can access inputs. Attestation proves fair execution.

### Confidential AI Inference
ML model inference where both the model and user inputs must remain confidential. TEEs prevent model extraction and input logging.

## Getting Started

This overview covers architectural concepts and security properties. For practical implementation:

- **Setup & Deployment**: See [README.md](../README.md) for installation and development setup
- **TEE Platform Configuration**: See [docs/TEE_SETUP.md](TEE_SETUP.md) for platform-specific deployment
- **Authentication Integration**: See [docs/SIWE.md](SIWE.md) for Web3 authentication
- **Security Considerations**: See [docs/SIDE_CHANNEL_ATTACKS.md](SIDE_CHANNEL_ATTACKS.md) for threat modeling

## Technical Stack

- **Runtime**: Node.js 24+ with NestJS 12
- **Language**: TypeScript 6
- **Package Manager**: pnpm
- **TEE Platforms**: AMD SEV-SNP, Intel TDX, AWS Nitro, Phala Network
- **Authentication**: SIWE (Sign-In with Ethereum)
- **API Documentation**: Swagger/OpenAPI
- **License**: GPL v3
