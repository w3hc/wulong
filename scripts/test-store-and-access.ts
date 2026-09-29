#!/usr/bin/env ts-node
/**
 * Test store and access flow with ML-KEM encryption on deployed server
 *
 * This script tests:
 * 1. Get attestation (with ML-KEM public key)
 * 2. Encrypt secret for client + server
 * 3. Store encrypted secret
 * 4. Access secret with SIWE authentication (using test wallet)
 *
 * Prerequisites:
 * - Wulong server running (local or Phala)
 *
 * Usage:
 *   WULONG_URL=http://localhost:3000 pnpm ts-node scripts/test-store-and-access.ts
 *   WULONG_URL=https://your-app.phala.network pnpm ts-node scripts/test-store-and-access.ts
 */

import { createMlKem1024 } from 'mlkem';
import * as crypto from 'crypto';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';

interface AttestationResponse {
  platform: string;
  report: string;
  measurement: string;
  timestamp: string;
  publicKey?: string;
  mlkemPublicKey?: string;
}

interface RecipientEntry {
  publicKey: string;
  ciphertext: string;
}

interface EncryptedPayload {
  recipients: RecipientEntry[];
  encryptedData: string;
  iv: string;
  authTag: string;
}

/**
 * Encrypt data for multiple recipients using ML-KEM-1024
 */
async function encryptMultiRecipient(
  plaintext: string,
  recipientPublicKeys: string[],
): Promise<EncryptedPayload> {
  const mlkem = await createMlKem1024();

  // Generate random AES-256 key
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  // Encrypt data with AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  let encrypted = cipher.update(plaintext, 'utf-8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Encapsulate AES key for each recipient
  const recipients: RecipientEntry[] = [];

  for (const pubKeyBase64 of recipientPublicKeys) {
    const publicKey = Buffer.from(pubKeyBase64, 'base64');

    if (publicKey.length !== 1568) {
      throw new Error(
        `Invalid ML-KEM public key size: ${publicKey.length} (expected 1568)`,
      );
    }

    const [kemCiphertext, sharedSecret] = mlkem.encap(publicKey);

    // XOR-encrypt the AES key with shared secret
    const kek = sharedSecret.subarray(0, 32);
    const encryptedAesKey = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      encryptedAesKey[i] = aesKey[i] ^ kek[i];
    }

    const combinedCiphertext = Buffer.concat([kemCiphertext, encryptedAesKey]);

    recipients.push({
      publicKey: pubKeyBase64,
      ciphertext: combinedCiphertext.toString('base64'),
    });
  }

  return {
    recipients,
    encryptedData: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

async function testStoreAndAccess() {
  console.log(
    '🧪 Testing ML-KEM store and access flow with SIWE authentication\n',
  );

  const serverUrl = process.env.WULONG_URL || 'http://localhost:3000';

  // Use test wallet (same as e2e tests)
  const testPrivateKey =
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
  const wallet = new Wallet(testPrivateKey);

  console.log(`🔗 Server: ${serverUrl}`);
  console.log(`👤 Test Wallet: ${wallet.address}\n`);

  try {
    // Step 1: Get attestation
    console.log('1️⃣  Getting server attestation...');
    const attestationResponse = await fetch(`${serverUrl}/chest/attestation`);
    if (!attestationResponse.ok) {
      throw new Error(
        `Attestation failed: ${attestationResponse.status} ${await attestationResponse.text()}`,
      );
    }

    const attestation: AttestationResponse = await attestationResponse.json();

    if (!attestation.mlkemPublicKey) {
      throw new Error('Server did not return ML-KEM public key');
    }

    console.log(`  ✅ Platform: ${attestation.platform}`);
    console.log(
      `  ✅ ML-KEM Public Key: ${attestation.mlkemPublicKey.substring(0, 32)}...`,
    );
    if (attestation.publicKey) {
      console.log(`  ✅ Server Ethereum Address: ${attestation.publicKey}`);
    }
    console.log(
      `  ⚠️  Measurement: ${attestation.measurement.substring(0, 32)}...`,
    );
    console.log();

    // Step 2: Generate client ML-KEM keypair
    console.log('2️⃣  Generating client ML-KEM keypair...');
    const mlkem = await createMlKem1024();
    const [clientPublicKey, clientPrivateKey] = mlkem.generateKeyPair();
    const clientPublicKeyBase64 =
      Buffer.from(clientPublicKey).toString('base64');
    console.log(`  ✅ Generated (1568 bytes)\n`);

    // Step 3: Encrypt secret
    const plaintext = '苟全性命於亂世，不求聞達於諸侯。';
    console.log('3️⃣  Encrypting secret for client + server...');
    console.log(`  📝 Plaintext: "${plaintext}"`);

    const encrypted = await encryptMultiRecipient(plaintext, [
      clientPublicKeyBase64,
      attestation.mlkemPublicKey,
    ]);

    console.log(
      `  ✅ Encrypted with ${encrypted.recipients.length} recipients\n`,
    );

    // Step 4: Store encrypted secret
    console.log('4️⃣  Storing encrypted secret on server...');
    const storeResponse = await fetch(`${serverUrl}/chest/store`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: encrypted,
        publicAddresses: [wallet.address],
      }),
    });

    if (!storeResponse.ok) {
      const errorText = await storeResponse.text();
      throw new Error(`Store failed: ${storeResponse.status} ${errorText}`);
    }

    const { slot } = await storeResponse.json();
    console.log(`  ✅ Stored in slot: ${slot}\n`);

    // Step 5: Get nonce for SIWE authentication
    console.log('5️⃣  Getting nonce for SIWE authentication...');
    const nonceResponse = await fetch(`${serverUrl}/auth/nonce`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: wallet.address }),
    });

    if (!nonceResponse.ok) {
      throw new Error(`Nonce request failed: ${nonceResponse.status}`);
    }

    const { nonce } = await nonceResponse.json();
    console.log(`  ✅ Nonce: ${nonce}\n`);

    // Step 6: Create and sign SIWE message
    console.log('6️⃣  Creating and signing SIWE message...');
    const domain = new URL(serverUrl).hostname;
    const siweMessage = new SiweMessage({
      domain: domain,
      address: wallet.address,
      uri: serverUrl,
      version: '1',
      chainId: 1,
      nonce: nonce,
      issuedAt: new Date().toISOString(),
      statement: 'Access encrypted secret from wulong',
    });

    const message = siweMessage.prepareMessage();
    const signature = await wallet.signMessage(message);

    console.log(`  ✅ SIWE message signed`);
    console.log(`     Domain: ${domain}`);
    console.log(`     Address: ${wallet.address}`);
    console.log(`     Signature: ${signature.substring(0, 32)}...\n`);

    // Step 7: Access secret with SIWE authentication
    console.log('7️⃣  Accessing secret (server-side decryption with SIWE)...');
    const accessResponse = await fetch(`${serverUrl}/chest/access/${slot}`, {
      method: 'GET',
      headers: {
        'x-siwe-message': Buffer.from(message).toString('base64'),
        'x-siwe-signature': signature,
      },
    });

    if (!accessResponse.ok) {
      const errorText = await accessResponse.text();
      throw new Error(`Access failed: ${accessResponse.status} ${errorText}`);
    }

    const { secret: decryptedSecret } = await accessResponse.json();
    console.log(`  📝 Server decrypted: "${decryptedSecret}"`);

    const serverMatch = decryptedSecret === plaintext;
    console.log(`  ${serverMatch ? '✅' : '❌'} Match: ${serverMatch}\n`);

    if (!serverMatch) {
      throw new Error('Server decryption mismatch!');
    }

    // Step 8: Summary
    console.log('📊 Test Summary:');
    console.log('  ✅ Server attestation retrieved');
    console.log('  ✅ Multi-recipient encryption successful');
    console.log('  ✅ Secret stored on server');
    console.log('  ✅ SIWE authentication successful');
    console.log('  ✅ Server-side decryption working');
    console.log('  ✅ Plaintext matches (end-to-end verified)\n');

    console.log(
      '🎉 All tests passed! Complete store+access flow working correctly.\n',
    );

    console.log('📋 What was tested:');
    console.log('  • ML-KEM-1024 quantum-resistant encryption');
    console.log('  • Multi-recipient encryption (client + server)');
    console.log('  • SIWE authentication with ethers wallet');
    console.log('  • Server-side ML-KEM decryption in TEE');
    console.log('  • End-to-end data integrity\n');
  } catch (error) {
    console.error('\n❌ Test failed:', error);
    console.error('\nTroubleshooting:');
    console.error('  - Is wulong server running?');
    console.error('  - Are ML-KEM keys configured?');
    console.error('  - Is the endpoint URL correct?');
    console.error(`  - Current URL: ${serverUrl}`);
    process.exit(1);
  }
}

testStoreAndAccess().catch((err) => {
  console.error('❌ Fatal error:', err);
  process.exit(1);
});
