import { Injectable, Logger } from '@nestjs/common';
import { KeyDerivationService } from '../keys/key-derivation.service';
import * as crypto from 'crypto';

/**
 * ML-KEM (Kyber) quantum-resistant encryption service
 *
 * This service provides ML-KEM decryption using ML-KEM-1024 (NIST FIPS 203).
 *
 * Architecture (Multi-Recipient):
 * 1. Client generates random AES-256 key
 * 2. Client encrypts data with AES-256-GCM
 * 3. For each recipient (client + server):
 *    - Encapsulate shared secret with recipient's ML-KEM public key
 *    - Derive a KEK from the shared secret with HKDF-SHA256
 *    - Wrap the AES key with AES-KW (RFC 3394) under the KEK
 *    - Store { publicKey, ciphertext (KEM ciphertext + wrapped AES key) }
 * 4. Client sends { version, recipients[], encryptedData, iv, authTag }
 * 5. Server finds its recipient entry (by public key)
 * 6. Server decapsulates, derives the KEK and unwraps the AES key
 * 7. Server decrypts data with AES-256-GCM
 *
 * Payloads without a version use the legacy v1 wrap (AES key XOR-ed with
 * the raw shared secret) and are still accepted so existing ciphertexts
 * remain readable.
 *
 * Compatible with w3pk's mlkemEncrypt/mlkemDecrypt functions.
 */

export interface RecipientEntry {
  publicKey: string; // Base64 ML-KEM-1024 public key (1568 bytes)
  ciphertext: string; // Base64 ML-KEM ciphertext (1568) + wrapped AES key (v2: 40, v1: 32)
}

export interface MultiRecipientEncryptedPayload {
  version?: 2; // Absent for legacy v1 payloads
  recipients: RecipientEntry[]; // Array of recipients
  encryptedData: string; // Base64 AES-256-GCM encrypted data (shared)
  iv: string; // Base64 IV (12 bytes)
  authTag: string; // Base64 auth tag (16 bytes)
}

const KEM_CIPHERTEXT_LENGTH = 1568;
const AES_KEY_LENGTH = 32;
const WRAPPED_KEY_LENGTH = { 1: 32, 2: 40 } as const;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEK_INFO = 'w3pk-mlkem-kek-v2';
const AES_KW_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

@Injectable()
export class MlKemEncryptionService {
  private readonly logger = new Logger(MlKemEncryptionService.name);
  private publicKey: Uint8Array | null = null;

  // Keys are derived in the enclave; this service never holds the private key
  constructor(private readonly keys: KeyDerivationService) {}

  onModuleInit() {
    this.publicKey = this.keys.getMlKemPublicKey();
  }

  /**
   * Get the admin's public key for client-side encryption
   */
  getPublicKey(): string | null {
    if (!this.publicKey) {
      return null;
    }
    return Buffer.from(this.publicKey).toString('base64');
  }

  /**
   * Check if encryption is available
   */
  isAvailable(): boolean {
    return this.publicKey !== null && this.keys.isAvailable();
  }

  /**
   * Decrypt a multi-recipient encrypted payload
   *
   * @param payload - Multi-recipient encrypted payload from client (w3pk format)
   * @returns Decrypted plaintext
   */
  decryptMultiRecipient(payload: MultiRecipientEncryptedPayload): string {
    if (!this.isAvailable() || !this.publicKey) {
      throw new Error('ML-KEM encryption not initialized');
    }

    try {
      const version = payload.version ?? 1;
      if (version !== 1 && version !== 2) {
        throw new Error(`Unsupported payload version: ${String(version)}`);
      }

      const serverPublicKeyBase64 = Buffer.from(this.publicKey).toString(
        'base64',
      );
      const recipientEntry = payload.recipients.find(
        (r) => r.publicKey === serverPublicKeyBase64,
      );

      if (!recipientEntry) {
        throw new Error('Server public key not found in recipients list');
      }

      const combinedCiphertext = Buffer.from(
        recipientEntry.ciphertext,
        'base64',
      );
      const expectedLength =
        KEM_CIPHERTEXT_LENGTH + WRAPPED_KEY_LENGTH[version];
      if (combinedCiphertext.length !== expectedLength) {
        throw new Error(
          `Invalid combined ciphertext size: ${combinedCiphertext.length} (expected ${expectedLength})`,
        );
      }

      const iv = Buffer.from(payload.iv, 'base64');
      if (iv.length !== IV_LENGTH) {
        throw new Error(
          `Invalid IV size: ${iv.length} (expected ${IV_LENGTH})`,
        );
      }
      const authTag = Buffer.from(payload.authTag, 'base64');
      if (authTag.length !== AUTH_TAG_LENGTH) {
        throw new Error(
          `Invalid auth tag size: ${authTag.length} (expected ${AUTH_TAG_LENGTH})`,
        );
      }

      const kemCiphertext = combinedCiphertext.subarray(
        0,
        KEM_CIPHERTEXT_LENGTH,
      );
      const wrappedKey = combinedCiphertext.subarray(KEM_CIPHERTEXT_LENGTH);

      const sharedSecret = this.keys.decapsulate(kemCiphertext);
      let aesKey: Buffer;
      try {
        aesKey =
          version === 2
            ? this.unwrapV2(sharedSecret, wrappedKey)
            : this.unwrapV1(sharedSecret, wrappedKey);
      } finally {
        sharedSecret.fill(0);
      }

      try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv, {
          authTagLength: AUTH_TAG_LENGTH,
        });
        decipher.setAuthTag(authTag);

        const decrypted = Buffer.concat([
          decipher.update(Buffer.from(payload.encryptedData, 'base64')),
          decipher.final(),
        ]);

        return decrypted.toString('utf-8');
      } finally {
        aesKey.fill(0);
      }
    } catch (error) {
      this.logger.error('Multi-recipient decryption failed:', error);
      throw new Error('Failed to decrypt multi-recipient data', {
        cause: error,
      });
    }
  }

  private unwrapV2(sharedSecret: Uint8Array, wrappedKey: Buffer): Buffer {
    const kek = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        sharedSecret,
        Buffer.alloc(0),
        KEK_INFO,
        AES_KEY_LENGTH,
      ),
    );
    try {
      const decipher = crypto.createDecipheriv(
        'id-aes256-wrap',
        kek,
        AES_KW_IV,
      );
      return Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
    } catch (error) {
      throw new Error('Wrapped AES key failed integrity check', {
        cause: error,
      });
    } finally {
      kek.fill(0);
    }
  }

  // Legacy: the AES key XOR-ed with the raw shared secret, no integrity check
  private unwrapV1(sharedSecret: Uint8Array, wrappedKey: Buffer): Buffer {
    const aesKey = Buffer.alloc(AES_KEY_LENGTH);
    for (let i = 0; i < AES_KEY_LENGTH; i++) {
      aesKey[i] = wrappedKey[i] ^ sharedSecret[i];
    }
    return aesKey;
  }
}
