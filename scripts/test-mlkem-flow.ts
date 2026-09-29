#!/usr/bin/env ts-node
/**
 * Test ML-KEM encryption flow without w3pk or UI
 *
 * This script simulates a complete client-server ML-KEM encryption flow:
 * 1. Get attestation (including TEE's public key)
 * 2. Encrypt secret with TEE's public key (simulating client)
 * 3. Store encrypted secret
 * 4. Retrieve and decrypt secret (simulating authorized access)
 *
 * Usage: pnpm ts-node scripts/test-mlkem-flow.ts
 */

import { createMlKem1024 } from 'mlkem';
import * as crypto from 'crypto';

interface EncryptedPayload {
  version: 2;
  recipients: { publicKey: string; ciphertext: string }[];
  encryptedData: string;
  iv: string;
  authTag: string;
}

const KEK_INFO = 'w3pk-mlkem-kek-v2';
const AES_KW_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

function deriveKek(sharedSecret: Uint8Array): Buffer {
  return Buffer.from(
    crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), KEK_INFO, 32),
  );
}

/**
 * Simulate client-side encryption (what w3pk would do)
 */
async function encryptForTEE(
  plaintext: string,
  teePublicKeyBase64: string,
): Promise<EncryptedPayload> {
  const mlkem = await createMlKem1024();
  const publicKeyBytes = Buffer.from(teePublicKeyBase64, 'base64');

  // Validate public key size
  if (publicKeyBytes.length !== 1568) {
    throw new Error(
      `Invalid ML-KEM public key size: ${publicKeyBytes.length} (expected 1568)`,
    );
  }

  // Generate random AES key and IV
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM

  // Encrypt data with AES-256-GCM
  console.log('  🔐 Encrypting with AES-256-GCM...');
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  let encrypted = cipher.update(plaintext, 'utf-8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();
  console.log(`  ✅ Encrypted (${encrypted.length} bytes)`);

  console.log('  📦 Encapsulating with TEE public key...');
  const [kemCiphertext, sharedSecret] = mlkem.encap(publicKeyBytes);
  console.log(`  ✅ Generated shared secret (${sharedSecret.length} bytes)`);

  // Wrap the AES key with AES-KW under an HKDF-derived KEK
  console.log('  🔑 Wrapping AES key with AES-KW...');
  const wrap = crypto.createCipheriv(
    'id-aes256-wrap',
    deriveKek(sharedSecret),
    AES_KW_IV,
  );
  const wrappedKey = Buffer.concat([wrap.update(aesKey), wrap.final()]);

  return {
    version: 2,
    recipients: [
      {
        publicKey: teePublicKeyBase64,
        ciphertext: Buffer.concat([kemCiphertext, wrappedKey]).toString(
          'base64',
        ),
      },
    ],
    encryptedData: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

/**
 * Simulate server-side decryption (what Wulong does)
 */
async function decryptPayload(
  payload: EncryptedPayload,
  privateKeyBase64: string,
): Promise<string> {
  const mlkem = await createMlKem1024();

  // Decode from base64
  const combined = Buffer.from(payload.recipients[0].ciphertext, 'base64');
  const encryptedData = Buffer.from(payload.encryptedData, 'base64');
  const iv = Buffer.from(payload.iv, 'base64');
  const authTag = Buffer.from(payload.authTag, 'base64');
  const privateKey = Buffer.from(privateKeyBase64, 'base64');

  // Validate sizes
  if (combined.length !== 1568 + 40) {
    throw new Error(
      `Invalid combined ciphertext size: ${combined.length} (expected 1608)`,
    );
  }

  console.log('  📦 Decapsulating with TEE private key...');
  const sharedSecret = mlkem.decap(combined.subarray(0, 1568), privateKey);
  console.log(`  ✅ Recovered shared secret (${sharedSecret.length} bytes)`);

  console.log('  🔑 Unwrapping AES key...');
  const unwrap = crypto.createDecipheriv(
    'id-aes256-wrap',
    deriveKek(sharedSecret),
    AES_KW_IV,
  );
  const aesKey = Buffer.concat([
    unwrap.update(combined.subarray(1568)),
    unwrap.final(),
  ]);

  // Decrypt data with AES-256-GCM
  console.log('  🔓 Decrypting with AES-256-GCM...');
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv, {
    authTagLength: 16,
  });
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  console.log(`  ✅ Decrypted (${decrypted.length} bytes)`);

  return decrypted.toString('utf-8');
}

async function testMLKEMFlow() {
  console.log('🧪 Testing ML-KEM encryption flow\n');

  // Step 1: Generate TEE keypair (simulating what Wulong does on startup)
  console.log('1️⃣  Generating TEE keypair...');
  const mlkem = await createMlKem1024();
  const [publicKey, privateKey] = mlkem.generateKeyPair();
  const publicKeyBase64 = Buffer.from(publicKey).toString('base64');
  const privateKeyBase64 = Buffer.from(privateKey).toString('base64');
  console.log(
    `  ✅ Public key: ${publicKeyBase64.substring(0, 32)}... (${publicKey.length} bytes)`,
  );
  console.log(
    `  ✅ Private key: ${privateKeyBase64.substring(0, 32)}... (${privateKey.length} bytes)\n`,
  );

  // Step 2: Client gets attestation (simulating GET /chest/attestation)
  console.log('2️⃣  Client: Getting TEE attestation...');
  const attestation = {
    platform: 'none',
    mlkemPublicKey: publicKeyBase64,
    measurements: null,
  };
  console.log(`  ✅ Received TEE public key\n`);

  // Step 3: Client encrypts secret (simulating w3pk)
  console.log('3️⃣  Client: Encrypting secret for TEE...');
  const plaintext = '苟全性命於亂世，不求聞達於諸侯。';
  console.log(`  📝 Plaintext: "${plaintext}"`);
  const encrypted = await encryptForTEE(plaintext, attestation.mlkemPublicKey);
  console.log(`  ✅ Encrypted payload ready\n`);

  // Step 4: Client stores encrypted secret (simulating POST /chest/store)
  console.log('4️⃣  Client: Storing encrypted secret...');
  const slot = crypto.randomBytes(32).toString('hex');
  console.log(`  ✅ Assigned slot: ${slot}\n`);

  // Step 5: Server decrypts secret (simulating GET /chest/access/:slot)
  console.log('5️⃣  Server: Decrypting secret...');
  const decrypted = await decryptPayload(encrypted, privateKeyBase64);
  console.log(`  📝 Decrypted: "${decrypted}"\n`);

  // Step 6: Verify
  console.log('6️⃣  Verification:');
  if (plaintext === decrypted) {
    console.log('  ✅ SUCCESS! Plaintext matches decrypted text');
    console.log('  ✅ ML-KEM encryption/decryption working correctly\n');
  } else {
    console.log('  ❌ FAILURE! Texts do not match');
    console.log(`  Expected: "${plaintext}"`);
    console.log(`  Got:      "${decrypted}"\n`);
    process.exit(1);
  }

  // Step 7: Show payload sizes
  console.log('📊 Payload sizes:');
  const recipientCiphertext = Buffer.from(
    encrypted.recipients[0].ciphertext,
    'base64',
  );
  console.log(
    `  • Recipient ciphertext: ${recipientCiphertext.length} bytes (1568 KEM + 40 wrapped key)`,
  );
  console.log(
    `  • AES encrypted data: ${Buffer.from(encrypted.encryptedData, 'base64').length} bytes`,
  );
  console.log(`  • IV: ${Buffer.from(encrypted.iv, 'base64').length} bytes`);
  console.log(
    `  • Auth tag: ${Buffer.from(encrypted.authTag, 'base64').length} bytes`,
  );
  console.log(
    `  • Total overhead: ~${recipientCiphertext.length + 12 + 16} bytes\n`,
  );

  console.log('🎉 All tests passed!');
}

testMLKEMFlow().catch((err) => {
  console.error('❌ Error:', err);
  process.exit(1);
});
