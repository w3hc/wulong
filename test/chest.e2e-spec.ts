import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import * as fs from 'fs';
import * as path from 'path';
import { MlKemEncryptionService } from '../src/encryption/mlkem-encryption.service';

// Helper to create a valid encrypted payload for testing
const createMockEncryptedPayload = () => {
  // Create 1600 bytes (1568 KEM + 32 AES key) as base64
  const ciphertextBytes = Buffer.alloc(1600);
  const ciphertextBase64 = ciphertextBytes.toString('base64');

  // Create 1568 bytes public key as base64
  const publicKeyBytes = Buffer.alloc(1568);
  const publicKeyBase64 = publicKeyBytes.toString('base64');

  return {
    recipients: [
      {
        publicKey: publicKeyBase64,
        ciphertext: ciphertextBase64,
      },
    ],
    encryptedData: Buffer.from('mock-encrypted-data').toString('base64'),
    iv: Buffer.from('mock-iv-12by').toString('base64'),
    authTag: Buffer.from('mock-tag-16bytes').toString('base64'),
  };
};

describe('Chest Endpoints (e2e)', () => {
  let app: INestApplication<App>;
  let wallet: Wallet;
  let wallet2: Wallet;
  const chestPath = path.join(process.cwd(), 'chest.json');

  beforeAll(async () => {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.KMS_URL = 'http://localhost:3001';
    // Keep the rate limiter out of the way; throttle.e2e-spec.ts covers it
    process.env.THROTTLE_LIMIT = '1000';
    // Set mock ML-KEM key for testing
    process.env.MLKEM_PRIVATE_KEY_BASE64 = Buffer.from(
      new Uint8Array(3168),
    ).toString('base64');

    // Create test wallets
    wallet = new Wallet(
      '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    );
    wallet2 = new Wallet(
      '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
    );

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(MlKemEncryptionService)
      .useValue({
        isAvailable: () => true,
        getPublicKey: () => 'mock-public-key',
        decryptMultiRecipient: jest
          .fn()
          .mockResolvedValue('decrypted-test-secret'),
      })
      .compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();
  });

  afterAll(async () => {
    await app.close();

    // Clean up test chest file
    if (fs.existsSync(chestPath)) {
      fs.unlinkSync(chestPath);
    }
  }, 10000);

  beforeEach(() => {
    // Clean up chest.json before each test
    if (fs.existsSync(chestPath)) {
      fs.unlinkSync(chestPath);
    }
  });

  describe('POST /chest/store', () => {
    it('should store a secret and return a slot', () => {
      return request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address],
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('slot');
          expect(typeof (res.body as { slot: string }).slot).toBe('string');
          expect((res.body as { slot: string }).slot).toMatch(/^[0-9a-f]{64}$/);
        });
    });

    it('should store a secret with multiple owners', () => {
      return request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address, wallet2.address],
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('slot');
        });
    });

    it('should reject invalid encrypted payload', () => {
      return request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: { recipients: [] },
          publicAddresses: [wallet.address],
        })
        .expect(400);
    });

    it('should reject empty publicAddresses array', () => {
      return request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [],
        })
        .expect(400);
    });

    it('should reject invalid Ethereum address', () => {
      return request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: ['invalid-address'],
        })
        .expect(400);
    });

    it('should reject malformed request (missing secret)', () => {
      return request(app.getHttpServer())
        .post('/chest/store')
        .send({
          publicAddresses: [wallet.address],
        })
        .expect(400);
    });

    it('should reject malformed request (missing publicAddresses)', () => {
      return request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
        })
        .expect(400);
    });

    it('should accept checksummed addresses', () => {
      return request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'],
        })
        .expect(201);
    });

    it('should create chest.json file if it does not exist', async () => {
      expect(fs.existsSync(chestPath)).toBe(false);

      await request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address],
        })
        .expect(201);

      expect(fs.existsSync(chestPath)).toBe(true);
    });
  });

  describe('GET /chest/access/:slot', () => {
    let slot: string;
    let nonce: string;

    beforeEach(async () => {
      // Store a secret first
      const storeResponse = await request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address],
        });

      slot = (storeResponse.body as { slot: string }).slot;

      // Generate a nonce for SIWE authentication
      const nonceResponse = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet.address });
      nonce = (nonceResponse.body as { nonce: string }).nonce;
    });

    it('should return secret for authorized owner with valid SIWE', async () => {
      // Create and sign SIWE message
      const siweMessage = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce,
        issuedAt: new Date().toISOString(),
      });

      const message = siweMessage.prepareMessage();
      const signature = await wallet.signMessage(message);

      return request(app.getHttpServer())
        .get(`/chest/access/${slot}`)
        .set('x-siwe-message', Buffer.from(message).toString('base64'))
        .set('x-siwe-signature', signature)
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('secret');
          expect((res.body as { secret: string }).secret).toBeDefined();
        });
    });

    it('should return 401 without SIWE authentication', () => {
      return request(app.getHttpServer())
        .get(`/chest/access/${slot}`)
        .expect(401);
    });

    it('should return 401 with invalid SIWE signature', () => {
      // Suppress expected error logs from signature verification
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const siweMessage = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce,
        issuedAt: new Date().toISOString(),
      });

      const message = siweMessage.prepareMessage();
      const invalidSignature =
        '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

      return request(app.getHttpServer())
        .get(`/chest/access/${slot}`)
        .set('x-siwe-message', Buffer.from(message).toString('base64'))
        .set('x-siwe-signature', invalidSignature)
        .expect(401)
        .then(() => {
          consoleErrorSpy.mockRestore();
        });
    });

    it('should return 403 when caller is not an owner', async () => {
      // Generate nonce for wallet2
      const nonceResponse = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet2.address });
      const nonce2 = (nonceResponse.body as { nonce: string }).nonce;

      // Create and sign SIWE message with wallet2 (not an owner)
      const siweMessage = new SiweMessage({
        domain: 'localhost',
        address: wallet2.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce2,
        issuedAt: new Date().toISOString(),
      });

      const message = siweMessage.prepareMessage();
      const signature = await wallet2.signMessage(message);

      return request(app.getHttpServer())
        .get(`/chest/access/${slot}`)
        .set('x-siwe-message', Buffer.from(message).toString('base64'))
        .set('x-siwe-signature', signature)
        .expect(403);
    });

    it('should return 404 for non-existent slot', async () => {
      const nonExistentSlot = 'b'.repeat(64);

      const siweMessage = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce,
        issuedAt: new Date().toISOString(),
      });

      const message = siweMessage.prepareMessage();
      const signature = await wallet.signMessage(message);

      return request(app.getHttpServer())
        .get(`/chest/access/${nonExistentSlot}`)
        .set('x-siwe-message', Buffer.from(message).toString('base64'))
        .set('x-siwe-signature', signature)
        .expect(404);
    });

    it('should allow multiple owners to access the same secret', async () => {
      // Store a secret with multiple owners
      const storeResponse = await request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address, wallet2.address],
        });

      const sharedSlot = (storeResponse.body as { slot: string }).slot;

      // First owner accesses
      const nonce1Response = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet.address });
      const nonce1 = (nonce1Response.body as { nonce: string }).nonce;

      const siweMessage1 = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce1,
        issuedAt: new Date().toISOString(),
      });

      const message1 = siweMessage1.prepareMessage();
      const signature1 = await wallet.signMessage(message1);

      await request(app.getHttpServer())
        .get(`/chest/access/${sharedSlot}`)
        .set('x-siwe-message', Buffer.from(message1).toString('base64'))
        .set('x-siwe-signature', signature1)
        .expect(200)
        .expect((res) => {
          expect((res.body as { secret: string }).secret).toBeDefined();
        });

      // Second owner accesses
      const nonce2Response = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet2.address });
      const nonce2 = (nonce2Response.body as { nonce: string }).nonce;

      const siweMessage2 = new SiweMessage({
        domain: 'localhost',
        address: wallet2.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce2,
        issuedAt: new Date().toISOString(),
      });

      const message2 = siweMessage2.prepareMessage();
      const signature2 = await wallet2.signMessage(message2);

      await request(app.getHttpServer())
        .get(`/chest/access/${sharedSlot}`)
        .set('x-siwe-message', Buffer.from(message2).toString('base64'))
        .set('x-siwe-signature', signature2)
        .expect(200)
        .expect((res) => {
          expect((res.body as { secret: string }).secret).toBeDefined();
        });
    });

    it('should handle case-insensitive address matching', async () => {
      // Store with lowercase address
      const storeResponse = await request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address.toLowerCase()],
        });

      const testSlot = (storeResponse.body as { slot: string }).slot;

      // Access with checksummed address (from wallet)
      const nonceResponse = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet.address });
      const testNonce = (nonceResponse.body as { nonce: string }).nonce;

      const siweMessage = new SiweMessage({
        domain: 'localhost',
        address: wallet.address, // Checksummed
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: testNonce,
        issuedAt: new Date().toISOString(),
      });

      const message = siweMessage.prepareMessage();
      const signature = await wallet.signMessage(message);

      return request(app.getHttpServer())
        .get(`/chest/access/${testSlot}`)
        .set('x-siwe-message', Buffer.from(message).toString('base64'))
        .set('x-siwe-signature', signature)
        .expect(200)
        .expect((res) => {
          expect((res.body as { secret: string }).secret).toBeDefined();
        });
    });
  });

  describe('Integration Flow (e2e)', () => {
    it('should complete full flow: store -> authenticate -> access', async () => {
      // Step 1: Store a secret
      const storeResponse = await request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address],
        })
        .expect(201);

      const slot = (storeResponse.body as { slot: string }).slot;
      expect(slot).toBeDefined();

      // Step 2: Generate nonce for authentication
      const nonceResponse = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet.address })
        .expect(201);

      const nonce = (nonceResponse.body as { nonce: string }).nonce;
      expect(nonce).toBeDefined();

      // Step 3: Create and sign SIWE message
      const siweMessage = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce,
        issuedAt: new Date().toISOString(),
      });

      const message = siweMessage.prepareMessage();
      const signature = await wallet.signMessage(message);

      // Step 4: Access the secret with authentication
      await request(app.getHttpServer())
        .get(`/chest/access/${slot}`)
        .set('x-siwe-message', Buffer.from(message).toString('base64'))
        .set('x-siwe-signature', signature)
        .expect(200)
        .expect((res) => {
          expect((res.body as { secret: string }).secret).toBeDefined();
        });
    });

    it('should store multiple secrets and access them independently', async () => {
      // Store first secret for wallet1
      const store1Response = await request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address],
        });

      const slot1 = (store1Response.body as { slot: string }).slot;

      // Store second secret for wallet2
      const store2Response = await request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet2.address],
        });

      const slot2 = (store2Response.body as { slot: string }).slot;

      // Access first secret with wallet1
      const nonce1Response = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet.address });
      const nonce1 = (nonce1Response.body as { nonce: string }).nonce;

      const siweMessage1 = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce1,
        issuedAt: new Date().toISOString(),
      });

      const message1 = siweMessage1.prepareMessage();
      const signature1 = await wallet.signMessage(message1);

      await request(app.getHttpServer())
        .get(`/chest/access/${slot1}`)
        .set('x-siwe-message', Buffer.from(message1).toString('base64'))
        .set('x-siwe-signature', signature1)
        .expect(200)
        .expect((res) => {
          expect((res.body as { secret: string }).secret).toBeDefined();
        });

      // Access second secret with wallet2
      const nonce2Response = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet2.address });
      const nonce2 = (nonce2Response.body as { nonce: string }).nonce;

      const siweMessage2 = new SiweMessage({
        domain: 'localhost',
        address: wallet2.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce2,
        issuedAt: new Date().toISOString(),
      });

      const message2 = siweMessage2.prepareMessage();
      const signature2 = await wallet2.signMessage(message2);

      await request(app.getHttpServer())
        .get(`/chest/access/${slot2}`)
        .set('x-siwe-message', Buffer.from(message2).toString('base64'))
        .set('x-siwe-signature', signature2)
        .expect(200)
        .expect((res) => {
          expect((res.body as { secret: string }).secret).toBeDefined();
        });

      // Verify wallet1 cannot access wallet2's secret
      const nonce3Response = await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address: wallet.address });
      const nonce3 = (nonce3Response.body as { nonce: string }).nonce;

      const siweMessage3 = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'http://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: nonce3,
        issuedAt: new Date().toISOString(),
      });

      const message3 = siweMessage3.prepareMessage();
      const signature3 = await wallet.signMessage(message3);

      await request(app.getHttpServer())
        .get(`/chest/access/${slot2}`)
        .set('x-siwe-message', Buffer.from(message3).toString('base64'))
        .set('x-siwe-signature', signature3)
        .expect(403);
    });
  });

  describe('GET /chest/attestation', () => {
    it('should return attestation report', () => {
      return request(app.getHttpServer())
        .get('/chest/attestation')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('platform');
          expect(res.body).toHaveProperty('report');
          expect(res.body).toHaveProperty('measurement');
          expect(res.body).toHaveProperty('timestamp');

          // Verify platform is one of the expected types
          expect([
            'amd-sev-snp',
            'intel-tdx',
            'aws-nitro',
            'phala',
            'none',
          ]).toContain((res.body as { platform: string }).platform);
        });
    });

    it('should return mock attestation in non-TEE environment', () => {
      return request(app.getHttpServer())
        .get('/chest/attestation')
        .expect(200)
        .expect((res) => {
          // In test environment, we expect mock attestation
          expect((res.body as { platform: string }).platform).toBe('none');
          expect((res.body as { measurement: string }).measurement).toContain(
            'MOCK',
          );
        });
    });

    it('should return attestation without authentication', () => {
      // Attestation should be publicly accessible - no auth required
      return request(app.getHttpServer()).get('/chest/attestation').expect(200);
    });

    it('should have valid timestamp format', () => {
      return request(app.getHttpServer())
        .get('/chest/attestation')
        .expect(200)
        .expect((res) => {
          const timestamp = (res.body as { timestamp: string }).timestamp;
          expect(timestamp).toBeDefined();
          // Verify it's a valid ISO timestamp
          expect(new Date(timestamp).toISOString()).toBe(timestamp);
        });
    });

    it('should return base64-encoded report', () => {
      return request(app.getHttpServer())
        .get('/chest/attestation')
        .expect(200)
        .expect((res) => {
          const report = (res.body as { report: string }).report;
          expect(report).toBeDefined();
          expect(typeof report).toBe('string');
          // Verify it's valid base64
          expect(() => Buffer.from(report, 'base64')).not.toThrow();
        });
    });
  });
});
