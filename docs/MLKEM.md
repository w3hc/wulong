# ML-KEM Quantum-Resistant Encryption

## Overview

Wulong implements **ML-KEM-1024** (Module-Lattice-Based Key-Encapsulation Mechanism) for post-quantum cryptographic security. ML-KEM is standardized by NIST as [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and provides security against both classical and quantum computer attacks.

## Table of Contents

- [Why ML-KEM?](#why-ml-kem)
- [Architecture](#architecture)
- [Multi-Recipient Encryption](#multi-recipient-encryption)
- [Security Properties](#security-properties)
- [API Reference](#api-reference)
- [Client Integration](#client-integration)
- [TEE Integration](#tee-integration)
- [Testing](#testing)
- [Migration Guide](#migration-guide)
- [FAQ](#faq)

## Why ML-KEM?

### The Quantum Threat

Current encryption standards like RSA and ECDH are vulnerable to quantum computers using **Shor's algorithm**. While cryptographically-relevant quantum computers (CRQC) are estimated to be 10-15 years away, encrypted data harvested today could be decrypted in the future (**harvest-now-decrypt-later** attacks).

### ML-KEM Advantages

✅ **Post-Quantum Secure**: Resistant to both classical and quantum attacks
✅ **NIST Standardized**: Official FIPS 203 standard (2024)
✅ **Efficient**: ~1-2ms encryption/decryption on modern hardware
✅ **Reasonable Size**: 1568-byte public keys, 3168-byte private keys
✅ **Hybrid Compatible**: Can be combined with classical crypto

## Architecture

### Traditional Encryption (Quantum-Vulnerable)

```
Client                          Server
  |                               |
  | Generate ECDH keypair         |
  | Compute shared secret   ━━━━━>| ECDH (vulnerable!)
  | Encrypt with AES              |
  | ━━━━━━━━━━━━━━━━━━━━━━━━━━━>|
  |                          Decrypt with ECDH
  |                          (Quantum computer can break this!)
```

### ML-KEM Encryption (Quantum-Safe)

```
Client                          Server (TEE)
  |                               |
  | Get ML-KEM public key   <━━━━| Sealed in TEE hardware
  | Encapsulate → ciphertext      |
  | Encrypt with AES              |
  | ━━━━━━━━━━━━━━━━━━━━━━━━━━━>|
  |                          Decapsulate → shared secret
  |                          Decrypt with AES
  |                          (Quantum-resistant!)
```

## Multi-Recipient Encryption

Wulong implements **multi-recipient ML-KEM encryption**, allowing multiple parties to independently decrypt the same data.

### How It Works

```
1. Client generates random AES-256 key (K)
2. Client encrypts data with K using AES-256-GCM
3. For each recipient (client, server, etc.):
   a. ML-KEM encapsulate → shared secret (SS)
   b. XOR-encrypt K with SS → encrypted_key
   c. Store: recipient_entry = {publicKey, ciphertext + encrypted_key}
4. Final payload = {recipients[], encryptedData, iv, authTag}
```

### Benefits

✅ **Privacy-First**: Client can decrypt locally without server
✅ **Flexible Access**: Server can decrypt for operations when needed
✅ **Single Storage**: One encrypted blob, multiple recipients
✅ **Independent Decryption**: No coordination needed between recipients

### Example Flow

```typescript
// Client side (using w3pk)
const encrypted = await w3pk.mlkemEncrypt(
  '苟全性命於亂世，不求聞達於諸侯。',
  [serverPublicKey]  // Server as recipient
);
// Client is automatically added as first recipient

// Client can decrypt locally (NO SERVER!)
const plaintext1 = await w3pk.mlkemDecrypt(encrypted);

// Server can decrypt for operations (with SIWE auth)
const plaintext2 = await fetch('/chest/access/slot123', {
  headers: { 'x-siwe-message': '...', 'x-siwe-signature': '...' }
});
```

## Security Properties

### Cryptographic Parameters

| Component | Algorithm | Security Level | Quantum Security |
|-----------|-----------|----------------|------------------|
| **Key Encapsulation** | ML-KEM-1024 | NIST Level 5 | 256-bit |
| **Symmetric Encryption** | AES-256-GCM | 256-bit classical | 128-bit quantum |
| **Key Derivation** | HKDF-SHA256 | 256-bit | 128-bit |
| **Authentication** | SIWE | Ethereum addresses | N/A |

### Attack Resistance

| Attack Vector | Mitigation |
|---------------|------------|
| **Quantum Computer (Shor's)** | ✅ ML-KEM immune to Shor's algorithm |
| **Harvest-Now-Decrypt-Later** | ✅ Data encrypted with ML-KEM at rest |
| **Man-in-the-Middle** | ✅ TEE attestation verification required |
| **Admin Access** | ✅ Private key sealed in TEE hardware |
| **Code Tampering** | ✅ RTMR3 in the quote identifies the app's compose file |
| **Replay Attacks** | ✅ SIWE nonces prevent replay |
| **Side-Channel** | ⚠️ TEE provides isolation (see [SIDE_CHANNEL_ATTACKS.md](SIDE_CHANNEL_ATTACKS.md)) |

### Key Sizes

```
ML-KEM-1024:
  Public Key:  1,568 bytes
  Private Key: 3,168 bytes
  Ciphertext:  1,568 bytes
  Shared Secret: 32 bytes

Per-Secret Overhead:
  Per Recipient: ~1,600 bytes (1,568 KEM + 32 encrypted AES key)
  Shared Data:   ~28 bytes (12 IV + 16 auth tag)

  Example: 2 recipients + 100 bytes data
  Total: ~3,328 bytes (vs ~145 bytes with ECDH)
```

## API Reference

### Server Endpoints

#### `GET /chest/attestation`

Get TEE attestation with server's ML-KEM public key.

**Response:**
```json
{
  "platform": "intel-tdx",
  "report": "base64_tdx_quote...",
  "measurements": { "mrtd": "...", "rtmr0": "...", "rtmr1": "...", "rtmr2": "...", "rtmr3": "..." },
  "eventLog": "[...]",
  "timestamp": "2026-03-22T10:30:00.000Z",
  "mlkemPublicKey": "ZLVMNpXCmEp7vhcylKzGXcx8...",
  "reportData": "0x..."
}

The full response is in [API_REFERENCE.md](API_REFERENCE.md#get-chestattestation).
```

**CRITICAL**: Clients MUST verify attestation before trusting `mlkemPublicKey`!

#### `POST /chest/store`

Store multi-recipient encrypted secret. Requires SIWE authentication (`x-siwe-message`, `x-siwe-signature`), and the caller must be one of `publicAddresses`; otherwise `401` or `403`.

**Request:**
```json
{
  "secret": {
    "recipients": [
      {
        "publicKey": "client_pubkey_base64...",
        "ciphertext": "client_ciphertext_base64..."
      },
      {
        "publicKey": "server_pubkey_base64...",
        "ciphertext": "server_ciphertext_base64..."
      }
    ],
    "encryptedData": "aes_encrypted_data_base64...",
    "iv": "iv_base64...",
    "authTag": "auth_tag_base64..."
  },
  "publicAddresses": ["0xClientAddress..."]
}
```

**Response:**
```json
{
  "slot": "05919c62d6a408cb98728c4c929ff0fd..."
}
```

#### `GET /chest/access/:slot`

Access secret (server-side decryption).

**Headers:**
```
x-siwe-message: base64(siweMessage)
x-siwe-signature: signatureHex
```

**Response:**
```json
{
  "secret": "decrypted plaintext"
}
```

### Server Service API

#### `MlKemEncryptionService`

```typescript
class MlKemEncryptionService {
  // Get server's public key for encryption
  getPublicKey(): string | null;

  // Check if encryption is available
  isAvailable(): boolean;

  // Decrypt multi-recipient payload
  decryptMultiRecipient(payload: MultiRecipientEncryptedPayload): string;

  // Legacy single-recipient decryption (deprecated)
  decrypt(payload: EncryptedPayload): string;

  // For testing only (client should encrypt)
  encrypt(plaintext: string): EncryptedPayload;
}
```

#### Types

```typescript
interface RecipientEntry {
  publicKey: string;  // Base64 ML-KEM-1024 public key (1568 bytes)
  ciphertext: string; // Base64: KEM ciphertext (1568) + encrypted AES key (32)
}

interface MultiRecipientEncryptedPayload {
  recipients: RecipientEntry[];  // Array of recipients
  encryptedData: string;         // Base64 AES-256-GCM encrypted data
  iv: string;                    // Base64 IV (12 bytes)
  authTag: string;               // Base64 auth tag (16 bytes)
}
```

## Client Integration

### Using w3pk SDK (Recommended)

w3pk provides seamless ML-KEM encryption with deterministic key derivation from Ethereum wallets.

```typescript
import { createWeb3Passkey } from 'w3pk';

// 1. Initialize w3pk
const w3pk = createWeb3Passkey();
await w3pk.login();

// 2. Get server attestation
const attestation = await fetch('https://vault.example.com/chest/attestation')
  .then(r => r.json());

// 3. CRITICAL: Verify attestation (future implementation)
// const isValid = await verifyAttestation(attestation, expectedMeasurement);
// if (!isValid) throw new Error('Invalid attestation!');

// 4. Encrypt for yourself + server
const encrypted = await w3pk.mlkemEncrypt(
  'my secret data',
  [attestation.mlkemPublicKey]  // Server as recipient
);

// 5. Store encrypted data
const { slot } = await fetch('https://vault.example.com/chest/store', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    ...siweHeaders, // signed by the STANDARD address, see 6b
  },
  body: JSON.stringify({
    secret: encrypted,
    publicAddresses: [await w3pk.getAddress('STANDARD')]
  })
}).then(r => r.json());

// 6a. Client-side decryption (PRIVACY-FIRST!)
const plaintext = await w3pk.mlkemDecrypt(encrypted);
// ✅ No server involved, complete privacy

// 6b. OR: Server-side decryption (for operations)
const siweMessage = await w3pk.signInWithEthereum(domain, { uri: origin });
const { secret } = await fetch(`https://vault.example.com/chest/access/${slot}`, {
  headers: {
    'x-siwe-message': Buffer.from(siweMessage.message).toString('base64'),
    'x-siwe-signature': siweMessage.signature
  }
}).then(r => r.json());
```

### Low-Level ML-KEM API

For custom implementations:

```typescript
import { deriveMLKemKeypair, mlkemEncrypt, mlkemDecrypt } from 'w3pk';

// Derive keypair from Ethereum private key
const keypair = await deriveMLKemKeypair(ethPrivateKey, 'my-app');

// Encrypt for multiple recipients
const encrypted = await mlkemEncrypt(plaintext, [
  publicKey1,
  publicKey2,
  publicKey3
]);

// Decrypt
const plaintext = await mlkemDecrypt(
  encrypted,
  keypair.privateKey,
  keypair.publicKey  // Optional: speeds up recipient lookup
);
```

## TEE Integration

### Key Derivation (Server Startup)

The server's ML-KEM-1024 key pair is never generated elsewhere, stored or read from env. `KeyDerivationService` derives it at boot from the dstack KMS (see [KEY_DERIVATION.md](./KEY_DERIVATION.md)):

```typescript
// src/keys/key-derivation.service.ts
const source = await this.dstack.getKey('wulong/mlkem-1024/v1', 'ed25519');
const seed = hkdfSync('sha256', source.key, 'wulong', info, 64); // d || z
const [publicKey, secretKey] = mlkem.deriveKeyPair(seed);
```

`MlKemEncryptionService` only gets the public key and a `decapsulate()` capability; the secret key stays inside `KeyDerivationService`.

### Attestation Response

`SecretService.getAttestation` builds `report_data` from the public keys, the TLS certificate and the client nonce, and asks `TeePlatformService` for a TDX quote over it through the dstack guest agent. The response carries the quote, its `measurements` (MRTD, RTMR0–3), the dstack `eventLog`, and the keys. See [TEE_SETUP.md](TEE_SETUP.md#how-attestation-works).

## Testing

This section explains how to test the ML-KEM multi-recipient encryption implementation both locally and on Phala Network.

### Local Testing (Development)

#### Step 1: Run the dstack Simulator

The server derives its keys from the dstack guest agent. Locally, run the simulator (dstack ≥ 0.6.0):

```bash
git clone https://github.com/Dstack-TEE/dstack
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```

#### Step 2: Configure Environment

Create or update `.env`:

```bash
DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

#### Step 3: Start Wulong Server

```bash
pnpm start:dev
```

The server should log:

```
WARN [KeyDerivationService] Keys derived from the dstack simulator (public root)
LOG  [KeyDerivationService] Keys derived: ML-KEM-1024 ZLVMNpXCmEp7vhcylKzGXcx8wVEcaQKI..., identity 0x...
```

Server will be available at `http://localhost:3000`

#### Step 4: Test ML-KEM Flow (Standalone)

Use the included test script to verify the basic flow:

```bash
pnpm ts-node scripts/test-mlkem-flow.ts
```

Expected output:

```
🧪 Testing ML-KEM encryption flow

1️⃣  Generating TEE keypair...
  ✅ Public key: ZLVMNpXCmEp7... (1568 bytes)

2️⃣  Client: Getting TEE attestation...
  ✅ Received TEE public key

3️⃣  Client: Encrypting secret for TEE...
  📦 Encapsulating with TEE public key...
  🔐 Encrypting with AES-256-GCM...
  ✅ Encrypted payload ready

4️⃣  Client: Storing encrypted secret...
  ✅ Assigned slot: 05919c62d6a408cb...

5️⃣  Server: Decrypting secret...
  🔓 Decrypting with AES-256-GCM...
  ✅ Decrypted: "This is my quantum-safe secret! 🔐"

6️⃣  Verification:
  ✅ SUCCESS! Plaintext matches decrypted text
  ✅ ML-KEM encryption/decryption working correctly

🎉 All tests passed!
```

#### Step 5: Test Complete Store+Access Flow

Test the full flow including SIWE authentication and server-side decryption:

```bash
pnpm ts-node scripts/test-store-and-access.ts
```

Expected output:

```
🧪 Testing ML-KEM store and access flow with SIWE authentication

🔗 Server: http://localhost:3000
👤 Test Wallet: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

1️⃣  Getting server attestation...
  ✅ Platform: none
  ✅ ML-KEM Public Key: k3VARNFcS4hWl6AfR0DMylysiyuCqgwO...
  ⚠️  Measurement: MOCK_MEASUREMENT...

2️⃣  Generating client ML-KEM keypair...
  ✅ Generated (1568 bytes)

3️⃣  Encrypting secret for client + server...
  📝 Plaintext: "🔐 My quantum-safe secret data! Testing store+access flow."
  ✅ Encrypted with 2 recipients

4️⃣  Storing encrypted secret on server...
  ✅ Stored in slot: c62d08e957b68109...

5️⃣  Getting nonce for SIWE authentication...
  ✅ Nonce: 4fhgr4TAfosNzZI3S

6️⃣  Creating and signing SIWE message...
  ✅ SIWE message signed
     Domain: localhost
     Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
     Signature: 0xf8db734904dfd0d0...

7️⃣  Accessing secret (server-side decryption with SIWE)...
  📝 Server decrypted: "🔐 My quantum-safe secret data! Testing store+access flow."
  ✅ Match: true

📊 Test Summary:
  ✅ Server attestation retrieved
  ✅ Multi-recipient encryption successful
  ✅ Secret stored on server
  ✅ SIWE authentication successful
  ✅ Server-side decryption working
  ✅ Plaintext matches (end-to-end verified)

🎉 All tests passed! Complete store+access flow working correctly.

📋 What was tested:
  • ML-KEM-1024 quantum-resistant encryption
  • Multi-recipient encryption (client + server)
  • SIWE authentication with ethers wallet
  • Server-side ML-KEM decryption in TEE
  • End-to-end data integrity
```

This script tests:
- ✅ **Multi-recipient encryption**: Client + server can both decrypt
- ✅ **Store endpoint**: Secret stored with access control
- ✅ **SIWE authentication**: Wallet-based authentication flow
- ✅ **Server-side decryption**: ML-KEM decryption in TEE
- ✅ **End-to-end verification**: Plaintext matches original

#### Step 6: Test with w3pk Client (Optional)

Create a test client using w3pk (in a separate directory or in w3pk repository):

```typescript
// test-wulong-mlkem.ts
import { createWeb3Passkey, mlkemEncrypt } from 'w3pk';
import { Wallet } from 'ethers';

async function testWulongMLKEM() {
  // 1. Get server's attestation (includes ML-KEM public key)
  const attestation = await fetch('http://localhost:3000/chest/attestation')
    .then(r => r.json());

  console.log('📋 Server Attestation:');
  console.log(`  Platform: ${attestation.platform}`);
  console.log(`  ML-KEM Public Key: ${attestation.mlkemPublicKey.substring(0, 32)}...`);

  // CRITICAL: In production, verify attestation here!
  // For local testing, we'll skip verification

  // 2. Create w3pk instance and login
  const w3pk = createWeb3Passkey();
  await w3pk.register({ username: 'test-user' });
  await w3pk.login();

  console.log(`\n👤 Client Address: ${await w3pk.getAddress('STANDARD')}`);

  // 3. Encrypt secret for yourself + server
  const plaintext = '苟全性命於亂世，不求聞達於諸侯。';
  console.log(`\n📝 Plaintext: "${plaintext}"`);

  const encrypted = await w3pk.mlkemEncrypt(
    plaintext,
    [attestation.mlkemPublicKey]  // Server as recipient
  );

  console.log(`\n🔐 Encrypted Payload:`);
  console.log(`  Recipients: ${encrypted.recipients.length}`);
  console.log(`  Encrypted Data: ${encrypted.encryptedData.substring(0, 32)}...`);

  // 4. Store encrypted secret on server
  const storeResponse = await fetch('http://localhost:3000/chest/store', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...siweHeaders, // signed by the STANDARD address, see 5b
    },
    body: JSON.stringify({
      secret: encrypted,
      publicAddresses: [await w3pk.getAddress('STANDARD')]
    })
  });

  const { slot } = await storeResponse.json();
  console.log(`\n✅ Stored in slot: ${slot}`);

  // 5a. Client-side decryption (privacy-first!)
  console.log(`\n🔓 Client-side decryption (no server involved):`);
  const clientDecrypted = await w3pk.mlkemDecrypt(encrypted);
  console.log(`  Decrypted: "${clientDecrypted}"`);
  console.log(`  ✅ Match: ${clientDecrypted === plaintext}`);

  // 5b. Server-side decryption (requires SIWE auth)
  console.log(`\n🔓 Server-side decryption (with SIWE auth):`);

  // Generate SIWE message
  const domain = 'localhost:3000';
  const origin = 'http://localhost:3000';
  const siweMessage = await w3pk.signInWithEthereum(domain, {
    uri: origin,
    statement: 'Access encrypted secret',
  });

  // Access secret via server
  const accessResponse = await fetch(`http://localhost:3000/chest/access/${slot}`, {
    headers: {
      'x-siwe-message': Buffer.from(siweMessage.message).toString('base64'),
      'x-siwe-signature': siweMessage.signature,
    }
  });

  const { secret: serverDecrypted } = await accessResponse.json();
  console.log(`  Decrypted: "${serverDecrypted}"`);
  console.log(`  ✅ Match: ${serverDecrypted === plaintext}`);

  console.log(`\n🎉 All tests passed! Multi-recipient ML-KEM working correctly.`);
}

testWulongMLKEM().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
```

Run the test:

```bash
pnpm ts-node test-wulong-mlkem.ts
```

#### Step 7: Test API with curl (Manual Testing)

##### Get Attestation

```bash
curl http://localhost:3000/chest/attestation | jq
```

Expected response:

```json
{
  "platform": "none",
  "report": "...",
  "measurements": null,
  "eventLog": null,
  "timestamp": "2026-03-22T...",
  "mlkemPublicKey": "ZLVMNpXCmEp7vhcylKzGXcx8wVEcaQKI..."
}
```

##### Store Encrypted Secret

You'll need to encrypt client-side first using w3pk, then:

```bash
curl -X POST http://localhost:3000/chest/store \
  -H "Content-Type: application/json" \
  -H "x-siwe-message: <base64-encoded SIWE message>" \
  -H "x-siwe-signature: <hex signature>" \
  -d '{
    "secret": {
      "recipients": [
        {
          "publicKey": "client_public_key_base64...",
          "ciphertext": "client_ciphertext_base64..."
        },
        {
          "publicKey": "server_public_key_base64...",
          "ciphertext": "server_ciphertext_base64..."
        }
      ],
      "encryptedData": "encrypted_data_base64...",
      "iv": "iv_base64...",
      "authTag": "auth_tag_base64..."
    },
    "publicAddresses": ["0xYourEthereumAddress..."]
  }'
```

#### Step 8: Run Unit and E2E Tests

```bash
# Run unit tests
pnpm test

# Run e2e tests
pnpm test:e2e
```

### Phala Network Testing (Production TEE)

#### Prerequisites

1. **Phala Account**: Register at [Phala Cloud](https://cloud.phala.network)
2. **Phala CLI**: Install with `npm install -g @phala/cli`
3. **Docker Hub**: For hosting container images
4. **ML-KEM Keys**: Generated and added to `.env.prod`

#### Step 1: Build and Deploy to Phala

Follow the complete deployment process:

```bash
# 1. Build the application
pnpm build

# 2. Build and push Docker image for AMD64
docker buildx build --platform linux/amd64 -t YOUR_USERNAME/wulong:latest --no-cache --push .

# 3. Deploy to Phala Cloud
phala deploy --interactive
# Select docker-compose.yml and .env.prod when prompted
# Choose tdx.small instance type for TEE support
```

See [PHALA_CONFIG.md](PHALA_CONFIG.md) for detailed instructions.

#### Step 2: Verify Deployment

Wait for deployment to complete:

```bash
phala cvms list
# Wait for status: running
```

Get your endpoint URL (format: `https://<APP_ID>-3000.<CLUSTER>.phala.network`)

#### Step 3: Test with Scripts

Run the complete store+access test against your Phala deployment:

```bash
WULONG_URL=https://your-app-id-3000.dstack-pha-prod9.phala.network pnpm ts-node scripts/test-store-and-access.ts
```

Expected output:

```
🧪 Testing ML-KEM store and access flow with SIWE authentication

🔗 Server: https://71ff0e26187be84e21c1f2553dd9dee39e8f7018-3000.dstack-pha-prod9.phala.network
👤 Test Wallet: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

1️⃣  Getting server attestation...
  ✅ Platform: intel-tdx
  ✅ ML-KEM Public Key: k3VARNFcS4hWl6AfR0DMylysiyuCqgwO...
  ⚠️  Measurement: 000000000000000000000000000000...

2️⃣  Generating client ML-KEM keypair...
  ✅ Generated (1568 bytes)

3️⃣  Encrypting secret for client + server...
  📝 Plaintext: "🔐 My quantum-safe secret data! Testing store+access flow."
  ✅ Encrypted with 2 recipients

4️⃣  Storing encrypted secret on server...
  ✅ Stored in slot: c62d08e957b68109924a63b3879e31caf3f9f9ccd0ab9b42befe082c645eae99

5️⃣  Getting nonce for SIWE authentication...
  ✅ Nonce: 4fhgr4TAfosNzZI3S

6️⃣  Creating and signing SIWE message...
  ✅ SIWE message signed
     Domain: 71ff0e26187be84e21c1f2553dd9dee39e8f7018-3000.dstack-pha-prod9.phala.network
     Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
     Signature: 0xf8db734904dfd0d0b294587ab09901...

7️⃣  Accessing secret (server-side decryption with SIWE)...
  📝 Server decrypted: "🔐 My quantum-safe secret data! Testing store+access flow."
  ✅ Match: true

📊 Test Summary:
  ✅ Server attestation retrieved
  ✅ Multi-recipient encryption successful
  ✅ Secret stored on server
  ✅ SIWE authentication successful
  ✅ Server-side decryption working
  ✅ Plaintext matches (end-to-end verified)

🎉 All tests passed! Complete store+access flow working correctly.

📋 What was tested:
  • ML-KEM-1024 quantum-resistant encryption
  • Multi-recipient encryption (client + server)
  • SIWE authentication with ethers wallet
  • Server-side ML-KEM decryption in TEE
  • End-to-end data integrity
```

**Key differences from local testing:**
- ✅ `platform: "intel-tdx"` (not "none") - Real TEE environment
- ✅ Hardware-backed ML-KEM private key (sealed in TEE)
- ✅ Cryptographic attestation from Intel TDX
- ✅ Production-grade security guarantees

#### Step 4: Verify Attestation

When deployed on Phala, the attestation will include:

```json
{
  "platform": "intel-tdx",
  "report": "base64_tdx_quote...",
  "measurements": { "mrtd": "...", "rtmr0": "...", "rtmr1": "...", "rtmr2": "...", "rtmr3": "..." },
  "eventLog": "[...]",
  "timestamp": "2026-03-22T...",
  "mlkemPublicKey": "server_public_key_from_tee..."
}
```

**CRITICAL:** Clients MUST verify:
1. ✅ `report` is a TDX quote with a valid signature (dcap-qvl, dstack-verifier or Phala's verifier)
2. ✅ `measurements.rtmr3` matches the value reproduced from the compose file ([TEE_SETUP.md](TEE_SETUP.md#measurements))
3. ✅ `reportData` commits to `mlkemPublicKey` and the client nonce ([KEY_DERIVATION.md](KEY_DERIVATION.md#verification))

#### Step 5: Client-Side Verification

```typescript
import { verifyPhalaAttestation } from 'w3pk'; // Future implementation

const attestation = await fetch('https://your-phala-endpoint/chest/attestation')
  .then(r => r.json());

// Verify attestation before trusting public key
const expectedMeasurement = 'sha256_of_published_source_code';
const isValid = await verifyPhalaAttestation(attestation, expectedMeasurement);

if (!isValid) {
  throw new Error('❌ TEE attestation verification failed! Do not proceed.');
}

// Now safe to encrypt with mlkemPublicKey
const encrypted = await w3pk.mlkemEncrypt(secret, [attestation.mlkemPublicKey]);
```

#### Step 6: Production Flow

The complete production flow on Phala:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Client gets attestation from Phala TEE                   │
│    GET https://your-app.phala.network/chest/attestation     │
│    Response: { platform: "intel-tdx", mlkemPublicKey, ... } │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Client verifies attestation                              │
│    ✅ Check RTMR3 matches the published compose file         │
│    ✅ Verify the TDX quote signature                         │
│    ✅ Confirm TEE platform is genuine                        │
│    ❌ REJECT if verification fails                           │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Client encrypts with w3pk                                │
│    const encrypted = await w3pk.mlkemEncrypt(                │
│      secret,                                                 │
│      [attestation.mlkemPublicKey]  // Server in TEE         │
│    );                                                        │
│    // Client is auto-added as first recipient               │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Client stores encrypted payload                          │
│    POST /chest/store (SIWE, caller in publicAddresses)      │
│    Body: { secret: encrypted, publicAddresses: [...] }      │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 5a. Client decrypts locally (privacy-first!)                │
│     const plaintext = await w3pk.mlkemDecrypt(encrypted);   │
│     // NO SERVER INVOLVED - complete privacy                │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 5b. OR: Server decrypts for operations                      │
│     GET /chest/access/:slot (with SIWE auth)                │
│     Server uses sealed private key to decrypt               │
│     Returns plaintext for internal operations               │
└─────────────────────────────────────────────────────────────┘
```

### Testing Checklist

#### Local Testing ✅

- [ ] Run the dstack simulator and set `DSTACK_SIMULATOR_ENDPOINT`
- [ ] Start server and verify keys derived
- [ ] Run `scripts/test-mlkem-flow.ts` successfully
- [ ] Run `scripts/test-store-and-access.ts` successfully
- [ ] Test with w3pk client (if available)
- [ ] Verify multi-recipient encryption works
- [ ] Verify both client-side and server-side decryption
- [ ] Test SIWE authentication flow
- [ ] Test error cases (wrong key, invalid payload, etc.)

#### Phala Testing ✅

- [ ] Build and push Docker image to Docker Hub
- [ ] Deploy to Phala Cloud with `phala deploy --interactive`
- [ ] Verify deployment status with `phala cvms list`
- [ ] Get attestation and verify `platform: "intel-tdx"`
- [ ] Verify ML-KEM keys are loaded in TEE
- [ ] Run `scripts/test-store-and-access.ts` against Phala endpoint
- [ ] Verify complete store+access flow works
- [ ] Test SIWE authentication with real wallet
- [ ] Verify attestation signature (Intel TDX-specific)
- [ ] Verify RTMR3 matches the value reproduced from the compose file
- [ ] Test with w3pk client integration
- [ ] Test with multiple concurrent clients
- [ ] Monitor instance costs and performance

### Security Considerations

#### Local Development

⚠️ **WARNING:** Local testing does NOT provide TEE security guarantees:
- Private key is in plaintext `.env` file
- No hardware isolation
- No attestation verification
- Admin can read secrets

**Use local testing ONLY for development and integration testing.**

#### Production (Phala TEE)

✅ **Security Properties:**
- Private key sealed in TEE hardware (cannot be extracted)
- Attestation cryptographically proves code integrity
- Admin cannot access secrets (even with root access)
- Quantum-resistant encryption (ML-KEM-1024)
- Multi-recipient design (client can decrypt independently)

**CRITICAL Client Responsibilities:**
1. **ALWAYS verify attestation** before encrypting
2. **Check RTMR3** matches the value reproduced from the compose file
3. **Verify the TDX quote signature**
4. **Reject invalid** attestations (do not proceed)

### Troubleshooting

#### "dstack v1 GetKey unavailable, encryption disabled"

**Solution:** Start the dstack simulator and set `DSTACK_SIMULATOR_ENDPOINT`. A 404 on `/v1/GetKey` means the simulator predates dstack 0.6.0.

#### "Invalid ML-KEM ciphertext size"

**Cause:** Client encrypted with wrong public key or corrupted payload

**Solution:** Verify client is using `mlkemPublicKey` from `/chest/attestation`

#### "Server public key not found in recipients list"

**Cause:** Client didn't include server as recipient

**Solution:** Pass server's public key to `w3pk.mlkemEncrypt(secret, [serverPublicKey])`

#### "Failed to decrypt secret"

**Possible causes:**
- Wrong private key on server
- Corrupted encrypted payload
- Client used wrong encryption algorithm

**Debug:** Check server logs for detailed error message

### Test Coverage

- ✅ ML-KEM keypair generation
- ✅ Multi-recipient encryption/decryption
- ✅ Client-side decryption (w3pk)
- ✅ Server-side decryption (TEE)
- ✅ SIWE authentication
- ✅ Invalid payload handling
- ✅ Error cases

## Migration Guide

### From Legacy Single-Recipient

Old format (deprecated):
```typescript
{
  ciphertext: "base64...",      // Single ML-KEM ciphertext
  encryptedData: "base64...",
  iv: "base64...",
  authTag: "base64..."
}
```

New format (multi-recipient):
```typescript
{
  recipients: [
    { publicKey: "base64...", ciphertext: "base64..." },
    { publicKey: "base64...", ciphertext: "base64..." }
  ],
  encryptedData: "base64...",
  iv: "base64...",
  authTag: "base64..."
}
```

Migration script:
```bash
# Re-encrypt existing secrets with multi-recipient format
pnpm ts-node scripts/migrate-to-multi-recipient.ts
```

### From No Encryption

If you have plaintext secrets in storage:

```typescript
// 1. Get all secrets
const secrets = await loadAllSecrets();

// 2. Encrypt each with ML-KEM
for (const [slot, entry] of Object.entries(secrets)) {
  const encrypted = await mlkemEncrypt(
    entry.secret,
    [clientPublicKey, serverPublicKey]
  );

  await store(slot, encrypted, entry.publicAddresses);
}
```

## FAQ

### General Questions

**Q: Is ML-KEM production-ready?**
A: Yes. ML-KEM is standardized by NIST as FIPS 203 (2024) and is considered production-ready for post-quantum cryptography.

**Q: What's the performance impact?**
A: Minimal. ML-KEM operations take ~1-2ms on modern hardware. Storage overhead is ~1.6KB per recipient.

**Q: Can I use ML-KEM without a TEE?**
A: Yes, but you lose the security guarantees. The private key would be accessible to administrators.

**Q: Is this compatible with existing systems?**
A: Yes. ML-KEM uses standard base64 encoding and can be integrated into existing HTTP APIs.

### Security Questions

**Q: What happens if quantum computers arrive sooner than expected?**
A: Your data is already protected. ML-KEM provides quantum resistance today.

**Q: How do I verify TEE attestation?**
A: Verify the TDX quote signature, check that `reportData` commits to the keys and your nonce, and compare `measurements.rtmr3` with the value reproduced from the compose file. See [TEE_SETUP.md](TEE_SETUP.md#measurements).

**Q: Can the server administrator access my secrets?**
A: In TEE deployment: No. The private key is sealed in hardware and cannot be extracted.
A: In local development: Yes. The private key is in `.env` (for testing only).

**Q: What if the server is compromised?**
A: Clients can decrypt locally using their own ML-KEM keys. The server is not required for decryption.

### Implementation Questions

**Q: How do I add a new recipient?**
A: Re-encrypt the data with the new recipient's public key included in the recipients array.

**Q: Can I remove a recipient?**
A: Re-encrypt without that recipient's public key. The old encrypted data should be deleted.

**Q: What's the maximum data size?**
A: No theoretical limit. The data is encrypted with AES-256-GCM, which handles arbitrary sizes.

**Q: How do I rotate keys?**
A: Change the derivation domain (`wulong/mlkem-1024/v1` to `/v2`) in a release that derives both generations and re-encapsulates the server entries inside the enclave. See [KEY_DERIVATION.md](./KEY_DERIVATION.md#rotation).

## Performance Benchmarks

### Local Development (Apple M2)

| Operation | Time | Notes |
|-----------|------|-------|
| Generate keypair | ~45ms | One-time |
| Encapsulate (per recipient) | ~0.9ms | Linear with recipients |
| Decapsulate | ~1.1ms | Per secret access |
| AES-256-GCM encrypt | ~0.1ms/KB | Data encryption |
| AES-256-GCM decrypt | ~0.1ms/KB | Data decryption |
| **Total encrypt (2 recipients)** | **~2.1ms** | Client-side |
| **Total decrypt** | **~1.2ms** | Server or client |

### Storage Overhead

| Scenario | Plaintext | Encrypted | Overhead |
|----------|-----------|-----------|----------|
| 1 recipient, 100 bytes | 100 | 1,728 | 17.3x |
| 2 recipients, 100 bytes | 100 | 3,328 | 33.3x |
| 2 recipients, 10 KB | 10,240 | 13,468 | 1.3x |
| 2 recipients, 1 MB | 1,048,576 | 1,051,904 | 1.003x |

**Conclusion:** Overhead is significant for small secrets (<1KB) but negligible for larger data.

## Roadmap

### Completed ✅

- [x] ML-KEM-1024 encryption/decryption
- [x] Multi-recipient support
- [x] w3pk integration
- [x] Server-side decryption
- [x] Client-side decryption
- [x] Deterministic key derivation (HKDF)
- [x] Documentation
- [x] Testing suite

### In Progress 🔄

- [ ] TEE attestation verification (w3pk)
- [ ] Phala Network deployment
- [ ] Example applications

### Future 🔮

- [ ] Hardware key storage (HSM)
- [ ] Key rotation automation
- [ ] Multi-signature support
- [ ] Threshold encryption
- [ ] Integration with other TEE platforms (only dstack on Intel TDX is supported)

## References

### Standards

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) - Official specification
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - PQC project
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) - Hybrid Public Key Encryption

### Libraries

- [mlkem](https://www.npmjs.com/package/mlkem) - WASM implementation used in wulong
- [w3pk](https://github.com/w3hc/w3pk) - Client-side integration
- [dstack](https://github.com/Dstack-TEE/dstack) - TEE guest OS and guest agent, reached through `src/keys/dstack-v1.client.ts`

### Documentation

- [Implementation Plan](MLKEM_IMPLEMENTATION_PLAN.md) - Development roadmap
- [Testing Guide](MLKEM_TESTING_GUIDE.md) - Testing procedures
- [Client Encryption](CLIENT_ENCRYPTION.md) - Client-side guide
- [Side-Channel Attacks](SIDE_CHANNEL_ATTACKS.md) - Security considerations

## Support

- **Issues**: [GitHub Issues](https://github.com/w3hc/wulong/issues)
- **Discussions**: [GitHub Discussions](https://github.com/w3hc/wulong/discussions)
- **Matrix**: [#wulong:matrix.org](https://matrix.to/#/#wulong:matrix.org)

---

**Last Updated:** 2026-03-22
**Version:** 1.0.0
**Status:** Production Ready
