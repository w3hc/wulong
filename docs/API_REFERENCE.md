# Wulong API Reference

Complete reference for all REST API endpoints in Wulong.

## Base URL

```
https://localhost:3000
```

**Note:** In development, use `-k` flag with curl to accept self-signed certificates.

## Table of Contents

- [Wulong API Reference](#wulong-api-reference)
  - [Base URL](#base-url)
  - [Table of Contents](#table-of-contents)
  - [Chest Endpoints](#chest-endpoints)
    - [GET /chest/attestation](#get-chestattestation)
    - [POST /chest/store](#post-cheststore)
    - [GET /chest/access/:slot](#get-chestaccessslot)
  - [Authentication Endpoints](#authentication-endpoints)
    - [POST /auth/nonce](#post-authnonce)
  - [Health Check Endpoints](#health-check-endpoints)
    - [GET /health](#get-health)
    - [GET /health/ready](#get-healthready)
    - [GET /health/live](#get-healthlive)
  - [Error Responses](#error-responses)
  - [Rate Limiting](#rate-limiting)
  - [Swagger/OpenAPI Documentation](#swaggeropenapi-documentation)
  - [Client Libraries](#client-libraries)
  - [Security Best Practices](#security-best-practices)
  - [Support](#support)
  - [Related Documentation](#related-documentation)

---

## Chest Endpoints

### GET /chest/attestation

Get TEE attestation proving the service cannot access user data.

**Authentication:** None (publicly accessible)

**Response:**

```typescript
{
  platform: 'amd-sev-snp' | 'intel-tdx' | 'aws-nitro' | 'phala' | 'none';
  report: string;           // Base64-encoded attestation report/quote from TEE
  measurement: string;      // Measurement/hash of the code running in the TEE
  timestamp: string;        // ISO 8601 timestamp when attestation was generated
  publicKey?: string;       // Public key of the TEE (if applicable)
  mlkemPublicKey?: string;  // ML-KEM-1024 public key for quantum-resistant encryption (base64)
}
```

**Example:**

```bash
# Request
curl -k https://localhost:3000/chest/attestation

# Response
{
  "platform": "intel-tdx",
  "report": "eyJhdHRlc3RhdGlvbiI6ICIuLi4ifQ==",
  "measurement": "abc123def456...",
  "timestamp": "2026-03-18T10:30:00.000Z",
  "mlkemPublicKey": "k3VARNFcS4hWl6AfR0DMy..."
}
```

**Use Cases:**
1. **Verify code integrity** - Compare `measurement` with published source code hash
2. **Get encryption key** - Use `mlkemPublicKey` to encrypt secrets client-side (quantum-resistant)
3. **Confirm TEE platform** - Check that service is running in genuine TEE hardware

**See also:** [Client-Side Encryption Guide](CLIENT_ENCRYPTION.md)

---

### POST /chest/store

Store a secret with owner-based access control.

**Authentication:** Required (SIWE)

**Headers:**
```
x-siwe-message: <base64-encoded SIWE message>
x-siwe-signature: <hex signature>
```

**Who may store:** any SIWE-authenticated caller, only if their own address is in `publicAddresses` (compared case-insensitively). A caller can share a secret with other addresses, but can't store one on behalf of addresses they don't control. Each SIWE nonce is single-use, so storing and then accessing takes two sign-ins.

**Request Body:**

```typescript
{
  secret: string;              // The secret to store (recommend encrypting with ML-KEM first)
  publicAddresses: string[];   // Array of Ethereum addresses that can access this secret
}
```

**Response:**

```typescript
{
  slot: string;  // Unique 64-character hex identifier for this secret
}
```

**Status Codes:**
- `201 Created` - Secret stored successfully
- `400 Bad Request` - Invalid request (empty secret, invalid addresses, etc.)
- `401 Unauthorized` - Missing or invalid SIWE authentication
- `403 Forbidden` - Caller is not one of `publicAddresses`

**Example:**

```bash
# Request
curl -k -X POST https://localhost:3000/chest/store \
  -H "Content-Type: application/json" \
  -H "x-siwe-message: <base64-encoded SIWE message>" \
  -H "x-siwe-signature: <hex signature>" \
  -d '{
    "secret": "苟全性命於亂世，不求聞達於諸侯。",
    "publicAddresses": ["0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"]
  }'

# Response
{
  "slot": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
}
```

**Security Recommendations:**

1. **Encrypt secrets client-side** with ML-KEM before storing:
   ```typescript
   // Get ML-KEM public key from attestation
   const attestation = await fetch('/chest/attestation').then(r => r.json());

   // Encrypt with ML-KEM (see Client-Side Encryption guide)
   const encrypted = await encryptWithMlKem(secret, attestation.mlkemPublicKey);

   // Store encrypted secret
   await fetch('/chest/store', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       'x-siwe-message': btoa(siweMessage),  // signed by myAddress
       'x-siwe-signature': signature,
     },
     body: JSON.stringify({
       secret: JSON.stringify(encrypted),
       publicAddresses: [myAddress]
     })
   });
   ```

2. **Use checksummed Ethereum addresses** - Both formats are accepted
3. **Store slot ID securely** - You'll need it to retrieve the secret later

**See also:** [Client-Side Encryption Guide](CLIENT_ENCRYPTION.md)

---

### GET /chest/access/:slot

Access a stored secret.

**Authentication:** Required (SIWE)

**Path Parameters:**
- `slot` - The slot identifier returned from `/chest/store`

**Headers:**
```
x-siwe-message: <base64-encoded SIWE message>
x-siwe-signature: <hex signature>
```

**Response:**

```typescript
{
  secret: string;  // The stored secret (decrypted if it was encrypted with ML-KEM)
}
```

**Status Codes:**
- `200 OK` - Secret retrieved successfully
- `401 Unauthorized` - Missing or invalid SIWE authentication
- `403 Forbidden` - Caller is not an owner of this secret
- `404 Not Found` - Slot does not exist

**Example:**

```bash
# Step 1: Get nonce
NONCE=$(curl -k -X POST https://localhost:3000/auth/nonce \
  -H 'Content-Type: application/json' \
  -d '{"address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"}' | jq -r '.nonce')

# Step 2: Create and sign SIWE message (using your wallet)
# Message format:
# localhost wants you to sign in with your Ethereum account:
# 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
#
# URI: https://localhost:3000
# Version: 1
# Chain ID: 1
# Nonce: <NONCE>
# Issued At: 2026-03-18T10:30:00.000Z

# Step 3: Access secret with SIWE authentication
curl -k https://localhost:3000/chest/access/a1b2c3d4... \
  -H "x-siwe-message: $(echo -n "$MESSAGE" | base64)" \
  -H "x-siwe-signature: $SIGNATURE"

# Response
{
  "secret": "苟全性命於亂世，不求聞達於諸侯。"
}
```

**TypeScript Example:**

```typescript
import { SiweMessage } from 'siwe';

// Get nonce
const { nonce } = await fetch('https://localhost:3000/auth/nonce', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: walletAddress }),
}).then(r => r.json());

// Create SIWE message
const siweMessage = new SiweMessage({
  domain: 'localhost',
  address: walletAddress,
  uri: 'https://localhost:3000',
  version: '1',
  chainId: 1,
  nonce: nonce,
  issuedAt: new Date().toISOString(),
});

const message = siweMessage.prepareMessage();
const signature = await wallet.signMessage(message);

// Access secret
const response = await fetch(`https://localhost:3000/chest/access/${slot}`, {
  headers: {
    'x-siwe-message': Buffer.from(message).toString('base64'),
    'x-siwe-signature': signature,
  },
});

const { secret } = await response.json();
console.log('Secret:', secret);
```

**Security Notes:**
- SIWE nonces are single-use and expire after 5 minutes
- Signatures must be valid for the authenticated Ethereum address
- Only addresses in the `publicAddresses` array can access the secret
- Case-insensitive address matching (checksummed or lowercase both work)

**See also:** [SIWE Authentication Guide](SIWE.md)

---

## Authentication Endpoints

### POST /auth/nonce

Generate a SIWE (Sign-In with Ethereum) nonce for authentication, bound to the address that will sign the message.

**Authentication:** None

**Request Body:**

```typescript
{
  address: string;  // Ethereum address that will sign the SIWE message
}
```

**Response:**

```typescript
{
  nonce: string;  // Random nonce for SIWE message (single-use, expires in 5 minutes)
}
```

**Example:**

```bash
# Request
curl -k -X POST https://localhost:3000/auth/nonce \
  -H 'Content-Type: application/json' \
  -d '{"address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"}'

# Response
{
  "nonce": "1a2b3c4d5e6f7890"
}
```

**Usage Flow:**

1. Call `/auth/nonce` with the signing address to get a fresh nonce
2. Create SIWE message with the nonce
3. Sign the message with your Ethereum wallet
4. Use the signature in `x-siwe-signature` header for protected endpoints

**Example SIWE Message Format:**

```
localhost wants you to sign in with your Ethereum account:
0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb

URI: https://localhost:3000
Version: 1
Chain ID: 1
Nonce: 1a2b3c4d5e6f7890
Issued At: 2026-03-18T10:30:00.000Z
```

**See also:** [SIWE Authentication Guide](SIWE.md)

---

## Health Check Endpoints

### GET /health

General health check endpoint.

**Authentication:** None

**Response:**

```typescript
{
  status: 'ok';
  timestamp: string;  // ISO 8601 timestamp
}
```

**Example:**

```bash
curl -k https://localhost:3000/health

# Response
{
  "status": "ok",
  "timestamp": "2026-03-18T10:30:00.000Z"
}
```

---

### GET /health/ready

Readiness probe for orchestration systems (Kubernetes, etc.).

**Authentication:** None

**Response:**

```typescript
{
  status: 'ready' | 'not ready';
  checks: {
    database?: boolean;
    tee?: boolean;
    encryption?: boolean;
  };
}
```

**Status Codes:**
- `200 OK` - Service is ready to accept traffic
- `503 Service Unavailable` - Service is not ready

**Example:**

```bash
curl -k https://localhost:3000/health/ready

# Response
{
  "status": "ready",
  "checks": {
    "tee": true,
    "encryption": true
  }
}
```

---

### GET /health/live

Liveness probe for orchestration systems.

**Authentication:** None

**Response:**

```typescript
{
  status: 'alive';
}
```

**Status Codes:**
- `200 OK` - Service is alive
- `503 Service Unavailable` - Service should be restarted

**Example:**

```bash
curl -k https://localhost:3000/health/live

# Response
{
  "status": "alive"
}
```

---

## Error Responses

All endpoints return consistent error responses:

```typescript
{
  statusCode: number;
  message: string;
  error?: string;  // Error type (BadRequest, Unauthorized, etc.)
}
```

**Common Status Codes:**
- `400 Bad Request` - Invalid request parameters or body
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Authenticated but not authorized
- `404 Not Found` - Resource does not exist
- `500 Internal Server Error` - Unexpected server error

**Example Error:**

```json
{
  "statusCode": 400,
  "message": "Secret cannot be empty",
  "error": "Bad Request"
}
```

---

## Rate Limiting

Every route is rate-limited per client IP, with a separate counter per route:

- **Default limit:** 10 requests per minute per route per IP (`THROTTLE_LIMIT`, `THROTTLE_TTL` in ms)
- **SIWE nonces:** at most 10,000 pending at once; past that, `POST /auth/nonce` returns 429 until some are used or expire

**Rate Limit Headers:**

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 42
Retry-After: 42
```

`Retry-After` is only sent with a 429. `X-RateLimit-Reset` and `Retry-After` are in seconds.

**Rate Limit Exceeded Response:**

```json
{
  "statusCode": 429,
  "message": "Too Many Requests",
  "error": "ThrottlerException"
}
```

---

## Swagger/OpenAPI Documentation

Interactive API documentation is available at:

```
https://localhost:3000
```

Features:
- Try out endpoints directly in the browser
- See request/response schemas
- View example requests and responses
- Download OpenAPI specification

---

## Client Libraries

**TypeScript/JavaScript:**
```bash
npm install mlkem siwe ethers
```

**Recommended Libraries:**
- `mlkem` - Quantum-resistant encryption
- `siwe` - Sign-In with Ethereum
- `ethers` - Ethereum wallet interaction
- `w3pk` - Web3 passkey SDK (for wallet + encryption)

**See also:**
- [Client-Side Encryption Guide](CLIENT_ENCRYPTION.md)
- [SIWE Authentication Guide](SIWE.md)

---

## Security Best Practices

1. **Always verify attestation** before encrypting secrets
   ```typescript
   const attestation = await fetch('/chest/attestation').then(r => r.json());
   if (attestation.measurement !== EXPECTED_MEASUREMENT) {
     throw new Error('Code measurement mismatch!');
   }
   ```

2. **Encrypt secrets client-side** with ML-KEM before storing
   - See [Client-Side Encryption Guide](CLIENT_ENCRYPTION.md)

3. **Use HTTPS in production** with real TLS certificates
   - Never use `-k` flag in production
   - Generate certificates inside TEE

4. **Store slot IDs securely**
   - Don't expose in URLs or logs
   - Consider encrypting slot IDs client-side

5. **Validate Ethereum addresses** before storing
   - Use checksummed addresses
   - Verify addresses are owned by intended users

6. **Handle SIWE nonces properly**
   - Request fresh nonce for each authentication
   - Don't reuse nonces
   - Check nonce expiration (5 minutes)

---

## Support

- **Documentation:** [docs/](.)
- **Issues:** File issues on GitHub repository
- **Security:** See [SIDE_CHANNEL_ATTACKS.md](SIDE_CHANNEL_ATTACKS.md)

---

## Related Documentation

- [Overview](OVERVIEW.md) - Project overview and architecture
- [Client-Side Encryption](CLIENT_ENCRYPTION.md) - Quantum-resistant encryption guide
- [TEE Setup](TEE_SETUP.md) - Platform-specific deployment
- [SIWE Authentication](SIWE.md) - Ethereum wallet authentication
- [Side Channel Attacks](SIDE_CHANNEL_ATTACKS.md) - Security considerations
