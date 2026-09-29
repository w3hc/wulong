# Client-Side Encryption with ML-KEM

This guide explains how to encrypt secrets on the client side using quantum-resistant ML-KEM-1024 encryption before sending them to the Wulong TEE service.

## Overview

**Architecture:**
```
Client (Browser/Node)          Wulong TEE Service
        |                              |
        |--1. Get attestation--------->|
        |<--   + ML-KEM public key-----|
        |                              |
        |--2. Verify attestation------>|
        |   (code measurement)         |
        |                              |
        |--3. Encrypt with ML-KEM----->|
        |   (quantum-resistant)        |
        |                              |
        |--4. Store encrypted--------->|
        |   secret in /chest/store     |
        |                              |
        |--5. Later: access secret---->|
        |   (with SIWE auth)           |
        |<--6. Decrypted plaintext-----|
```

**Security Properties:**
- ✅ **Quantum-resistant**: ML-KEM-1024 (NIST FIPS 203)
- ✅ **TEE-verified**: Attestation proves code integrity
- ✅ **Admin cannot decrypt**: Private key only in TEE
- ✅ **End-to-end encryption**: Plaintext never leaves client until TEE

## Quick Verification

Before implementing client-side encryption, verify that the TEE service has ML-KEM encryption configured:

```bash
# Check if ML-KEM public key is available
curl -k https://localhost:3000/chest/attestation | jq .mlkemPublicKey

# Expected output: Base64-encoded public key (1568 bytes when decoded)
# "k3VARNFcS4hWl6AfR0DMylysiyuCqgwO..."
```

**Note:** The `-k` flag accepts self-signed certificates (development only). In production with real TLS certificates from Let's Encrypt or a CA, omit the `-k` flag.

**If `mlkemPublicKey` is `null`:**

The admin needs to generate and configure ML-KEM keys on the server:

```bash
# On the TEE server
pnpm ts-node scripts/generate-admin-keypair.ts

# Add the output to .env file:
# ADMIN_MLKEM_PUBLIC_KEY=...
# ADMIN_MLKEM_PRIVATE_KEY=...

# Restart the service
pnpm start:dev  # or in production: node dist/main.js
```

**Verify the configuration:**

```bash
# Check attestation includes all fields
curl -k https://localhost:3000/chest/attestation | jq

# Expected output:
# {
#   "platform": "none",              # or "intel-tdx", "amd-sev-snp", etc.
#   "report": "...",                 # Base64 attestation report
#   "measurement": "...",            # Code hash
#   "timestamp": "2026-03-18T...",
#   "mlkemPublicKey": "k3VAR..."    # ← Should be present
# }
```

## Installation

### Browser (TypeScript/JavaScript)

```bash
npm install mlkem
```

### Ethereum Wallet Integration (w3pk)

If you're using w3pk SDK for Ethereum wallet authentication:

```bash
npm install mlkem w3pk
```

## Client-Side Encryption

### Step 1: Get Attestation & Public Key

```typescript
import { createMlKem1024 } from 'mlkem';

// Get attestation with ML-KEM public key
const response = await fetch('https://your-tee-service.com/chest/attestation');
const attestation = await response.json();

console.log('Platform:', attestation.platform);        // 'intel-tdx', 'amd-sev-snp', etc.
console.log('Measurement:', attestation.measurement);  // Code hash
console.log('ML-KEM Public Key:', attestation.mlkemPublicKey);

// Verify measurement matches published source code
const expectedMeasurement = 'abc123...'; // From GitHub release
if (attestation.measurement !== expectedMeasurement) {
  throw new Error('Code measurement mismatch! Service may be compromised');
}

// Now you can trust the ML-KEM public key
const adminPublicKey = Buffer.from(attestation.mlkemPublicKey, 'base64');
```

### Step 2: Encrypt Secret with ML-KEM

```typescript
// Initialize ML-KEM
const mlkem = await createMlKem1024();

// Your secret data
const plaintext = JSON.stringify({
  apiKey: 'sk-1234567890',
  password: '苟全性命於亂世，不求聞達於諸侯。',
  metadata: 'any additional data'
});

// Encapsulate with admin's public key
const [ciphertext, sharedSecret] = mlkem.encap(adminPublicKey);

// Encrypt data with AES-256-GCM using shared secret
const crypto = window.crypto || require('crypto');
const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV

const encoder = new TextEncoder();
const data = encoder.encode(plaintext);

const key = await crypto.subtle.importKey(
  'raw',
  sharedSecret,
  { name: 'AES-GCM' },
  false,
  ['encrypt']
);

const encrypted = await crypto.subtle.encrypt(
  {
    name: 'AES-GCM',
    iv: iv,
  },
  key,
  data
);

// Extract authentication tag (last 16 bytes)
const encryptedArray = new Uint8Array(encrypted);
const encryptedData = encryptedArray.slice(0, -16);
const authTag = encryptedArray.slice(-16);

// Prepare payload for server
const payload = {
  ciphertext: Buffer.from(ciphertext).toString('base64'),
  encryptedData: Buffer.from(encryptedData).toString('base64'),
  iv: Buffer.from(iv).toString('base64'),
  authTag: Buffer.from(authTag).toString('base64'),
};
```

### Step 3: Store Encrypted Secret

Storing requires SIWE authentication, and the signing address must be one of `publicAddresses`. Sign in as shown in Step 4; each nonce is single-use, so sign in again before accessing.

```typescript
// Store encrypted secret on server
const storeResponse = await fetch('https://your-tee-service.com/chest/store', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-siwe-message': Buffer.from(message).toString('base64'),
    'x-siwe-signature': signature,
  },
  body: JSON.stringify({
    secret: JSON.stringify(payload),  // Store encrypted payload as string
    publicAddresses: ['0xYourEthereumAddress'],
  }),
});

const { slot } = await storeResponse.json();
console.log('Secret stored in slot:', slot);

// Save slot ID for later retrieval
localStorage.setItem('secretSlot', slot);
```

### Step 4: Retrieve & Decrypt (Later)

```typescript
import { SiweMessage } from 'siwe';

// Get nonce for SIWE
const nonceResponse = await fetch('https://your-tee-service.com/auth/nonce', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: yourEthereumAddress }),
});
const { nonce } = await nonceResponse.json();

// Sign SIWE message with your Ethereum wallet
const siweMessage = new SiweMessage({
  domain: window.location.host,
  address: yourEthereumAddress,
  uri: window.location.origin,
  version: '1',
  chainId: 1,
  nonce: nonce,
  issuedAt: new Date().toISOString(),
});

const message = siweMessage.prepareMessage();
const signature = await wallet.signMessage(message); // or w3pk.signMessage()

// Retrieve encrypted secret
const slot = localStorage.getItem('secretSlot');
const accessResponse = await fetch(`https://your-tee-service.com/chest/access/${slot}`, {
  headers: {
    'x-siwe-message': Buffer.from(message).toString('base64'),
    'x-siwe-signature': signature,
  },
});

const { secret } = await accessResponse.json();

// Secret is already decrypted by TEE!
const decryptedData = JSON.parse(secret);
console.log('API Key:', decryptedData.apiKey);
console.log('Password:', decryptedData.password);
```

## Helper Function: Complete Encryption Wrapper

```typescript
import { createMlKem1024 } from 'mlkem';

export async function encryptForTee(
  plaintext: string,
  teeServiceUrl: string
): Promise<{ payload: string; adminPublicKey: string }> {
  // Get attestation
  const attestation = await fetch(`${teeServiceUrl}/chest/attestation`).then(r => r.json());

  if (!attestation.mlkemPublicKey) {
    throw new Error('ML-KEM encryption not available on this service');
  }

  // Verify attestation (you should check measurement here)
  // if (attestation.measurement !== expectedMeasurement) {
  //   throw new Error('Code measurement mismatch!');
  // }

  const adminPublicKey = Buffer.from(attestation.mlkemPublicKey, 'base64');

  // Initialize ML-KEM
  const mlkem = await createMlKem1024();

  // Encapsulate
  const [ciphertext, sharedSecret] = mlkem.encap(adminPublicKey);

  // Encrypt with AES-256-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  const key = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  );

  const encryptedArray = new Uint8Array(encrypted);
  const encryptedData = encryptedArray.slice(0, -16);
  const authTag = encryptedArray.slice(-16);

  const payload = JSON.stringify({
    ciphertext: Buffer.from(ciphertext).toString('base64'),
    encryptedData: Buffer.from(encryptedData).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    authTag: Buffer.from(authTag).toString('base64'),
  });

  return {
    payload,
    adminPublicKey: attestation.mlkemPublicKey,
  };
}

// Usage
const { payload } = await encryptForTee('my-secret-data', 'https://tee-service.com');

await fetch('https://tee-service.com/chest/store', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    ...siweHeaders, // signed by myAddress, see Step 4
  },
  body: JSON.stringify({
    secret: payload,
    publicAddresses: [myAddress],
  }),
});
```

## Integration with w3pk SDK

```typescript
import { createWeb3Passkey } from 'w3pk';
import { encryptForTee } from './encryption-helper';

const w3pk = createWeb3Passkey();

// Login with passkey
await w3pk.login();

// Encrypt secret
const { payload } = await encryptForTee(
  JSON.stringify({ apiKey: 'sk-123', password: 'pass' }),
  'https://tee-service.com'
);

// Store encrypted secret
const response = await fetch('https://tee-service.com/chest/store', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    ...siweHeaders, // signed by w3pk.getAddress(), see Step 4
  },
  body: JSON.stringify({
    secret: payload,
    publicAddresses: [w3pk.getAddress()],
  }),
});

const { slot } = await response.json();
console.log('Stored in slot:', slot);

// Later: retrieve with SIWE
const nonce = await fetch('https://tee-service.com/auth/nonce', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: await w3pk.getAddress() }),
}).then(r => r.json()).then(d => d.nonce);

const { signature, address } = await w3pk.signMessage(/* SIWE message */, {
  signingMethod: 'SIWE',
});

const { secret } = await fetch(`https://tee-service.com/chest/access/${slot}`, {
  headers: {
    'x-siwe-message': /* base64 encoded SIWE message */,
    'x-siwe-signature': signature,
  },
}).then(r => r.json());

console.log('Decrypted:', secret); // TEE already decrypted it
```

## Security Considerations

### 1. Always Verify Attestation

```typescript
// DON'T: Skip attestation verification
const attestation = await fetch('/chest/attestation').then(r => r.json());
// Use public key directly ❌

// DO: Verify measurement first
const attestation = await fetch('/chest/attestation').then(r => r.json());
const expectedMeasurement = getExpectedMeasurementFromGitHub();
if (attestation.measurement !== expectedMeasurement) {
  throw new Error('Code measurement mismatch!');
}
// Now safe to use public key ✅
```

### 2. Store Slot IDs Securely

```typescript
// For sensitive data, don't store slot IDs in localStorage
// Instead, derive them deterministically or store server-side
const slot = await storeSecret(...);

// Option 1: Derive from user's wallet
const derivedSlot = keccak256(userAddress + secretType);

// Option 2: Store server-side with authentication
await saveSlotToProfile(slot, userId);
```

### 3. Use HTTPS

Always use HTTPS to prevent man-in-the-middle attacks on the attestation response.

### 4. Rotate Keys

The admin's ML-KEM keypair should be rotated periodically. Plan for key rotation:

```typescript
// Check key version in attestation
if (attestation.keyVersion < MINIMUM_KEY_VERSION) {
  throw new Error('TEE key too old, please upgrade');
}
```

## Quantum Resistance

**Why ML-KEM-1024?**
- NIST FIPS 203 standard
- Security Level 5 (256-bit classical security)
- Resistant to Shor's algorithm (breaks RSA/ECDSA)
- Lattice-based cryptography (Learning With Errors)

**Timeline:**
- Current: Safe against classical computers
- 2030s: Quantum computers may break RSA/ECDSA
- ML-KEM-1024: Safe against quantum computers

## Performance

**ML-KEM-1024 Performance:**
- Key generation: ~0.5ms
- Encapsulation: ~1ms
- Decapsulation: ~1ms
- AES-256-GCM: ~0.1ms per KB

**Total encryption overhead:** ~2ms for typical secrets

## Troubleshooting

### "ML-KEM encryption not available"

The service hasn't configured ML-KEM keys. Contact the admin to run:
```bash
pnpm ts-node scripts/generate-admin-keypair.ts
```

### "Code measurement mismatch"

The code running in the TEE doesn't match the expected measurement. This could mean:
1. The service was updated (check for new releases)
2. The TEE is compromised (DO NOT send secrets)

### "Decryption failed"

1. Check that the ciphertext, IV, and authTag are correctly base64-encoded
2. Verify the payload structure matches the expected format
3. Ensure the ML-KEM ciphertext is exactly 1568 bytes

## Next Steps

- [TEE Setup Guide](TEE_SETUP.md) - Deploy your own TEE service
- [SIWE Authentication](SIWE.md) - Ethereum wallet authentication
- [API Reference](../README.md#api-endpoints) - Complete API documentation

## References

- [ML-KEM (NIST FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [mlkem Package](https://www.npmjs.com/package/mlkem)
- [w3pk SDK](https://github.com/Web3-Wallet/web3-passkey-sdk)
