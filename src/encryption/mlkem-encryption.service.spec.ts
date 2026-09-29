import { Logger } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import {
  MlKemEncryptionService,
  MultiRecipientEncryptedPayload,
} from './mlkem-encryption.service';
import { KeyDerivationService } from '../keys/key-derivation.service';
import { createMlKem1024 } from 'mlkem';
import * as crypto from 'crypto';

describe('MlKemEncryptionService', () => {
  let service: MlKemEncryptionService;
  let mlkem: Awaited<ReturnType<typeof createMlKem1024>>;
  let serverPublicKey: Uint8Array;
  let serverPrivateKey: Uint8Array;

  const createService = async (keysDerived: boolean) => {
    const keys = {
      isAvailable: () => keysDerived,
      getMlKemPublicKey: () => (keysDerived ? serverPublicKey : null),
      decapsulate: (ciphertext: Uint8Array) =>
        mlkem.decap(ciphertext, serverPrivateKey),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MlKemEncryptionService,
        { provide: KeyDerivationService, useValue: keys },
      ],
    }).compile();

    const created = module.get<MlKemEncryptionService>(MlKemEncryptionService);
    created.onModuleInit();
    return created;
  };

  // Returns the error thrown by fn, so both its message and cause can be checked
  const thrownBy = (fn: () => unknown): Error => {
    try {
      fn();
    } catch (error) {
      return error as Error;
    }
    throw new Error('expected fn to throw');
  };

  beforeAll(async () => {
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    mlkem = await createMlKem1024();
    [serverPublicKey, serverPrivateKey] = mlkem.generateKeyPair();
  });

  beforeEach(async () => {
    service = await createService(true);
  });

  describe('onModuleInit', () => {
    it('should expose the derived public key', () => {
      expect(service.isAvailable()).toBe(true);
      expect(service.getPublicKey()).toBe(
        Buffer.from(serverPublicKey).toString('base64'),
      );
    });

    it('should be unavailable when keys were not derived', async () => {
      const testService = await createService(false);

      expect(testService.isAvailable()).toBe(false);
      expect(testService.getPublicKey()).toBeNull();
    });
  });

  describe('getPublicKey', () => {
    it('should return base64 encoded public key', () => {
      const publicKeyBase64 = service.getPublicKey();
      expect(publicKeyBase64).toBeTruthy();

      const publicKey = Buffer.from(publicKeyBase64!, 'base64');
      expect(publicKey.length).toBe(1568);
    });
  });

  describe('isAvailable', () => {
    it('should return true when keys are loaded', () => {
      expect(service.isAvailable()).toBe(true);
    });
  });

  describe('Multi-Recipient Encryption/Decryption', () => {
    let clientPublicKey: Uint8Array;

    beforeEach(() => {
      // Generate client keypair
      [clientPublicKey] = mlkem.generateKeyPair();
    });

    it('should decrypt multi-recipient payload encrypted by client', async () => {
      const plaintext = 'Test secret message for multi-recipient encryption';

      // Client encrypts for themselves + server
      const encrypted = await encryptMultiRecipient(plaintext, [
        Buffer.from(clientPublicKey).toString('base64'),
        service.getPublicKey()!,
      ]);

      // Server decrypts
      const decrypted = service.decryptMultiRecipient(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle multiple recipients correctly', async () => {
      const plaintext = 'Secret for multiple recipients';

      // Generate additional recipient keypair
      const [recipient2Public] = mlkem.generateKeyPair();

      const encrypted = await encryptMultiRecipient(plaintext, [
        Buffer.from(clientPublicKey).toString('base64'),
        service.getPublicKey()!,
        Buffer.from(recipient2Public).toString('base64'),
      ]);

      expect(encrypted.recipients.length).toBe(3);

      // Server should still be able to decrypt
      const decrypted = service.decryptMultiRecipient(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should throw error if server public key not in recipients', async () => {
      const plaintext = 'Secret not encrypted for server';

      // Encrypt only for client (not server)
      const encrypted = await encryptMultiRecipient(plaintext, [
        Buffer.from(clientPublicKey).toString('base64'),
      ]);

      const error = thrownBy(() => service.decryptMultiRecipient(encrypted));
      expect(error.message).toBe('Failed to decrypt multi-recipient data');
      expect((error.cause as Error).message).toBe(
        'Server public key not found in recipients list',
      );
    });

    it('should throw error if ciphertext size is invalid', async () => {
      const plaintext = 'Test';
      const encrypted = await encryptMultiRecipient(plaintext, [
        service.getPublicKey()!,
      ]);

      // Corrupt ciphertext size
      encrypted.recipients[0].ciphertext =
        Buffer.from('invalid').toString('base64');

      const error = thrownBy(() => service.decryptMultiRecipient(encrypted));
      expect(error.message).toBe('Failed to decrypt multi-recipient data');
      expect((error.cause as Error).message).toMatch(
        /Invalid combined ciphertext size/,
      );
    });

    it('should throw error if auth tag is invalid', async () => {
      const plaintext = 'Test';
      const encrypted = await encryptMultiRecipient(plaintext, [
        service.getPublicKey()!,
      ]);

      // Corrupt auth tag
      encrypted.authTag = Buffer.from('corrupted_tag_12').toString('base64');

      expect(() => service.decryptMultiRecipient(encrypted)).toThrow(
        'Failed to decrypt multi-recipient data',
      );
    });

    it('should handle empty plaintext', async () => {
      const plaintext = '';
      const encrypted = await encryptMultiRecipient(plaintext, [
        service.getPublicKey()!,
      ]);

      const decrypted = service.decryptMultiRecipient(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle large plaintext', async () => {
      const plaintext = 'A'.repeat(100000); // 100KB
      const encrypted = await encryptMultiRecipient(plaintext, [
        service.getPublicKey()!,
      ]);

      const decrypted = service.decryptMultiRecipient(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle Unicode characters', async () => {
      const plaintext = '你好世界 🔐 Test émojis Spëcîål çhãrs';
      const encrypted = await encryptMultiRecipient(plaintext, [
        service.getPublicKey()!,
      ]);

      const decrypted = service.decryptMultiRecipient(encrypted);
      expect(decrypted).toBe(plaintext);
    });
    it('should reject a tampered wrapped key', async () => {
      const encrypted = await encryptMultiRecipient('Test', [
        service.getPublicKey()!,
      ]);
      const combined = Buffer.from(
        encrypted.recipients[0].ciphertext,
        'base64',
      );
      combined[combined.length - 1] ^= 0x01;
      encrypted.recipients[0].ciphertext = combined.toString('base64');

      const error = thrownBy(() => service.decryptMultiRecipient(encrypted));
      expect(error.message).toBe('Failed to decrypt multi-recipient data');
      expect((error.cause as Error).message).toBe(
        'Wrapped AES key failed integrity check',
      );
    });

    it('should reject an IV that is not 12 bytes', async () => {
      const encrypted = await encryptMultiRecipient('Test', [
        service.getPublicKey()!,
      ]);
      encrypted.iv = crypto.randomBytes(16).toString('base64');

      const error = thrownBy(() => service.decryptMultiRecipient(encrypted));
      expect((error.cause as Error).message).toBe(
        'Invalid IV size: 16 (expected 12)',
      );
    });

    it('should reject a truncated auth tag', async () => {
      const encrypted = await encryptMultiRecipient('Test', [
        service.getPublicKey()!,
      ]);
      encrypted.authTag = Buffer.from(encrypted.authTag, 'base64')
        .subarray(0, 4)
        .toString('base64');

      const error = thrownBy(() => service.decryptMultiRecipient(encrypted));
      expect((error.cause as Error).message).toBe(
        'Invalid auth tag size: 4 (expected 16)',
      );
    });

    it('should reject an unknown payload version', async () => {
      const encrypted = await encryptMultiRecipient('Test', [
        service.getPublicKey()!,
      ]);
      (encrypted as { version: number }).version = 3;

      const error = thrownBy(() => service.decryptMultiRecipient(encrypted));
      expect((error.cause as Error).message).toBe(
        'Unsupported payload version: 3',
      );
    });
  });

  describe('Legacy v1 payloads', () => {
    it('should decrypt a payload without a version', async () => {
      const plaintext = 'Legacy XOR-wrapped payload';
      const encrypted = await encryptMultiRecipientV1(plaintext, [
        service.getPublicKey()!,
      ]);

      expect(encrypted.version).toBeUndefined();
      expect(service.decryptMultiRecipient(encrypted)).toBe(plaintext);
    });

    it('should reject a v2-sized ciphertext without a version', async () => {
      const encrypted = await encryptMultiRecipient('Test', [
        service.getPublicKey()!,
      ]);
      delete encrypted.version;

      const error = thrownBy(() => service.decryptMultiRecipient(encrypted));
      expect((error.cause as Error).message).toMatch(
        /Invalid combined ciphertext size: 1608 \(expected 1600\)/,
      );
    });
  });

  describe('Error handling for uninitialized service', () => {
    it('should throw error when decryptMultiRecipient called without initialization', async () => {
      const uninitializedService = await createService(false);

      const dummyPayload = {
        recipients: [],
        encryptedData: 'dummy',
        iv: 'dummy',
        authTag: 'dummy',
      };

      expect(() =>
        uninitializedService.decryptMultiRecipient(dummyPayload),
      ).toThrow('ML-KEM encryption not initialized');
    });
  });
});

/**
 * Helper: Encrypt data for multiple recipients using ML-KEM-1024
 * (Mirrors w3pk's mlkemEncrypt, v2 format)
 */
async function encryptMultiRecipient(
  plaintext: string,
  recipientPublicKeys: string[],
): Promise<MultiRecipientEncryptedPayload> {
  return encryptWith(plaintext, recipientPublicKeys, (sharedSecret, aesKey) => {
    const kek = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        sharedSecret,
        Buffer.alloc(0),
        'w3pk-mlkem-kek-v2',
        32,
      ),
    );
    const cipher = crypto.createCipheriv(
      'id-aes256-wrap',
      kek,
      Buffer.from('A6A6A6A6A6A6A6A6', 'hex'),
    );
    return Buffer.concat([cipher.update(aesKey), cipher.final()]);
  }).then((payload) => ({ version: 2 as const, ...payload }));
}

/**
 * Helper: Encrypt with the legacy v1 wrap (AES key XOR-ed with shared secret)
 */
function encryptMultiRecipientV1(
  plaintext: string,
  recipientPublicKeys: string[],
): Promise<MultiRecipientEncryptedPayload> {
  return encryptWith(plaintext, recipientPublicKeys, (sharedSecret, aesKey) => {
    const wrapped = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      wrapped[i] = aesKey[i] ^ sharedSecret[i];
    }
    return wrapped;
  });
}

async function encryptWith(
  plaintext: string,
  recipientPublicKeys: string[],
  wrap: (sharedSecret: Uint8Array, aesKey: Buffer) => Buffer,
): Promise<MultiRecipientEncryptedPayload> {
  const mlkem = await createMlKem1024();

  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf-8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  const recipients = recipientPublicKeys.map((pubKeyBase64) => {
    const [kemCiphertext, sharedSecret] = mlkem.encap(
      Buffer.from(pubKeyBase64, 'base64'),
    );
    return {
      publicKey: pubKeyBase64,
      ciphertext: Buffer.concat([
        kemCiphertext,
        wrap(sharedSecret, aesKey),
      ]).toString('base64'),
    };
  });

  return {
    recipients,
    encryptedData: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}
