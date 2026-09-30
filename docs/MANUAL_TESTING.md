# Manual Testing Guide

This guide walks you through manually testing the `store` and `access` endpoints using Swagger UI.

## Prerequisites

- Development server running: `npm run start:dev`
- Swagger UI available at: https://localhost:3000 (not served in production)
- Node.js installed (for generating SIWE headers)

## Test Wallet

For testing purposes, use Hardhat's default test account:

- **Address**: `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
- **Private Key**: `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`

> ⚠️ **Never use this wallet on mainnet or with real funds!**

## Step-by-Step Testing

### Step 1: Get Authentication Nonce

1. In Swagger, find **POST /auth/nonce** and expand it
2. Click **"Try it out"**
3. Set the request body to the address that will sign, e.g. `{ "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" }`
4. Click **"Execute"**

**Expected Response (201):**
```json
{
  "nonce": "PPYcS5Li8uFiANPZQ",
  "issuedAt": "2026-03-18T16:02:48.284Z",
  "expiresAt": "2026-03-18T16:07:48.284Z"
}
```

📋 **Copy the `nonce` value** - you'll need it for Step 2.

> 💡 Nonces expire in 5 minutes. If your nonce expires, generate a new one.

---

### Step 2: Generate SIWE Headers

Create a file `generate-siwe-headers.mjs` with the following content:

```javascript
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';

// Check if nonce is provided as command line argument
const nonce = process.argv[2];

if (!nonce) {
  console.error('\n❌ Error: Nonce is required\n');
  console.log('Usage: node generate-siwe-headers.mjs <NONCE>\n');
  console.log('Example: node generate-siwe-headers.mjs PPYcS5Li8uFiANPZQ\n');
  process.exit(1);
}

// Hardhat test wallet (Account #0)
// WARNING: This is a well-known test private key from Hardhat's default accounts.
// NEVER use this key with real funds or on mainnet!
const wallet = new Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');

const siweMessage = new SiweMessage({
  domain: 'localhost',
  address: wallet.address,
  uri: 'https://localhost:3000',
  version: '1',
  chainId: 1,
  nonce: nonce,
  issuedAt: new Date().toISOString(),
});

const message = siweMessage.prepareMessage();
const signature = await wallet.signMessage(message);

console.log('\n=== SIWE Authentication Headers ===\n');
console.log('x-siwe-message:', Buffer.from(message).toString('base64'));
console.log('\nx-siwe-signature:', signature);
console.log('\nWallet address:', wallet.address);
console.log('\n');
```

Run the script with your nonce:

```bash
node generate-siwe-headers.mjs PPYcS5Li8uFiANPZQ
```

**Output:**
```
=== SIWE Authentication Headers ===

x-siwe-message: bG9jYWxob3N0IHdhbnRzIHlvdSB0byBzaWduIGluIHdpdGggeW91ciBFdGhlcmV1bSBhY2NvdW50OgoweGYzOUZkNmU1MWFhZDg4RjZGNGNlNmFCODgyNzI3OWNmZkZiOTIyNjYKCgpVUkk6IGh0dHA6Ly9sb2NhbGhvc3Q6MzAwMApWZXJzaW9uOiAxCkNoYWluIElEOiAxCk5vbmNlOiBQUFljUzVMaTh1RmlBTlBaUQpJc3N1ZWQgQXQ6IDIwMjYtMDMtMThUMTY6MDM6MTUuOTA3Wg==

x-siwe-signature: 0xe6993b8d8609e68e4490bb48316c09456cce2593a68cc017253a86892eea472a30328baa43e38e6aac5a07c0588dd3fae3cf9be271ff36eda5f3801914547c9f1c

Wallet address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

📋 **Copy both header values** - you'll need them for Step 3.

---

### Step 3: Store a Secret

1. Open https://localhost:3000 in your browser
2. Find **POST /chest/store** and expand it
3. Click **"Try it out"**
4. Add the authentication headers from Step 2:
   - **x-siwe-message**: `<paste base64 value from Step 2>`
   - **x-siwe-signature**: `<paste signature from Step 2>`
5. Use this example request body (the signing wallet must be one of `publicAddresses`):
   ```json
   {
     "secret": "苟全性命於亂世，不求聞達於諸侯。",
     "publicAddresses": ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]
   }
   ```
6. Click **"Execute"**

**Expected Response (201):**
```json
{
  "slot": "047d4396cbbf44a41c61d0c75f3bf6e322df175140b877f503442d5caeccdb2b"
}
```

📋 **Copy the `slot` value** - you'll need it for Step 4.

---

### Step 4: Access the Secret

1. In Swagger, find **GET /chest/access/{slot}** and expand it
2. Click **"Try it out"**
3. In the **slot** field, paste your slot from Step 3
4. Add fresh authentication headers — each nonce is single-use, so repeat Steps 1 and 2 first:
   - **x-siwe-message**: `<paste base64 value from Step 2>`
   - **x-siwe-signature**: `<paste signature from Step 2>`
5. Click **"Execute"**

**Expected Response (200):**
```json
{
  "secret": "苟全性命於亂世，不求聞達於諸侯。"
}
```

✅ Success! You've retrieved your secret with proper authentication.

---

## Testing Edge Cases

### Test 1: Access Without Authentication

Try accessing the secret without the headers:

1. Go to **GET /chest/access/{slot}**
2. Enter your slot
3. **Don't add any headers**
4. Click **"Execute"**

**Expected Response (401):**
```json
{
  "message": "Unauthorized",
  "statusCode": 401
}
```

---

### Test 2: Store for Another Address

The signing wallet must be one of `publicAddresses`. Try to store a secret only for someone else:

1. Generate SIWE headers using the default test wallet (Steps 1 and 2)
2. Go to **POST /chest/store**, add the headers, and use `publicAddresses: ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8"]`
3. Click **"Execute"**

**Expected Response (403):**
```json
{
  "message": "Store denied: caller must be one of publicAddresses",
  "error": "Forbidden",
  "statusCode": 403
}
```

---

### Test 3: Access Non-Existent Slot

Try accessing a slot that doesn't exist:

1. Go to **GET /chest/access/{slot}**
2. Enter a fake slot: `0000000000000000000000000000000000000000000000000000000000000000`
3. Add valid SIWE headers
4. Click **"Execute"**

**Expected Response (404):**
```json
{
  "message": "Not Found",
  "statusCode": 404
}
```

---

### Test 4: Store with Multiple Owners

Store a secret accessible by multiple addresses (signed by one of them):

```json
{
  "secret": "shared-secret",
  "publicAddresses": [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
  ]
}
```

Both addresses should be able to access the secret with their respective SIWE authentication.

---

## Troubleshooting

### "Nonce expired" Error
- Nonces expire after 5 minutes
- Generate a new nonce and SIWE headers

### "Invalid signature" Error
- Make sure the nonce in the SIWE message matches the one from the server
- Ensure you're using the correct private key for the address in `publicAddresses`

### "Forbidden" Error
- Verify the wallet address used for signing matches one in `publicAddresses` (both for store and access)
- Addresses are case-insensitive but must match

---

## Additional Endpoints

### GET /chest/attestation

Test the TEE attestation endpoint (no authentication required):

1. Go to **GET /chest/attestation**
2. Click **"Try it out"**
3. Click **"Execute"**

**Expected Response (200):**
```json
{
  "platform": "none",
  "report": "base64-encoded-string",
  "measurements": null,
  "eventLog": null,
  "timestamp": "2026-03-18T16:02:48.284Z",
  ...
}
```

> 💡 Without the dstack socket or simulator, the platform is "none", the report is a placeholder, and `measurements` is `null`. With `DSTACK_SIMULATOR_ENDPOINT` set, it is "intel-tdx" with a simulator quote. Production refuses to start without dstack.
