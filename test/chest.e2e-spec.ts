import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { createHmac } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { MlKemEncryptionService } from '../src/encryption/mlkem-encryption.service';
import { KeyDerivationService } from '../src/keys/key-derivation.service';
import { buildReportData } from '../src/attestation/report-data';
import { TeeTlsService } from '../src/tls/tee-tls.service';

const serverPublicKey = Buffer.alloc(1568).toString('base64');

// Helper to create a valid encrypted payload for testing
const createMockEncryptedPayload = () => {
  // Create 1600 bytes (1568 KEM + 32 AES key) as base64
  const ciphertextBytes = Buffer.alloc(1600);
  const ciphertextBase64 = ciphertextBytes.toString('base64');

  return {
    recipients: [
      {
        publicKey: serverPublicKey,
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

  const siweHeaders = async (signer: Wallet) => {
    const nonceResponse = await request(app.getHttpServer())
      .post('/auth/nonce')
      .send({ address: signer.address });
    const nonce = (nonceResponse.body as { nonce: string }).nonce;

    const message = new SiweMessage({
      domain: 'localhost',
      address: signer.address,
      uri: 'http://localhost:3000',
      version: '1',
      chainId: 1,
      nonce,
      issuedAt: new Date().toISOString(),
    }).prepareMessage();

    return {
      'x-siwe-message': Buffer.from(message).toString('base64'),
      'x-siwe-signature': await signer.signMessage(message),
    };
  };

  const storeAs = async (signer: Wallet, body: object) => {
    const headers = await siweHeaders(signer);
    return request(app.getHttpServer())
      .post('/chest/store')
      .set(headers)
      .send(body);
  };

  beforeAll(async () => {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    // Keep the rate limiter out of the way; throttle.e2e-spec.ts covers it
    process.env.THROTTLE_LIMIT = '1000';

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
        getPublicKey: () => serverPublicKey,
        decryptMultiRecipient: jest
          .fn()
          .mockResolvedValue('decrypted-test-secret'),
      })
      .overrideProvider(KeyDerivationService)
      .useValue({
        getMlKemPublicKey: () => new Uint8Array(1568).fill(0x01),
        getIdentityPublicKey: () => new Uint8Array(65).fill(0x04),
        getKeyManifest: () => ({
          manifest: {
            appId: '0x1111111111111111111111111111111111111111',
            mlkemPublicKeyHash: '0x' + '22'.repeat(32),
            relayer: '0x' + '55'.repeat(20),
            epoch: 1,
          },
          signature: '0x' + '33'.repeat(65),
        }),
        getIdentitySignatureChain: () => [new Uint8Array([0xaa])],
        getRelayerAddress: () => '0x' + '55'.repeat(20),
        getRelayerSignatureChain: () => [new Uint8Array([0xbb])],
        getRelayerPublicKey: () => new Uint8Array(65).fill(0x04),
        macChestEntry: (data: Uint8Array) =>
          createHmac('sha256', 'e2e').update(data).digest(),
      })
      .overrideProvider(TeeTlsService)
      .useValue({
        getServerOptions: () => null,
        getLeafCertificateDer: () => new Uint8Array([0x30, 0x03]),
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
    it('should store a secret and return a slot', async () => {
      const res = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [wallet.address],
      });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('slot');
      expect(typeof (res.body as { slot: string }).slot).toBe('string');
      expect((res.body as { slot: string }).slot).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should store a secret with multiple owners', async () => {
      const res = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [wallet.address, wallet2.address],
      });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('slot');
    });

    it('should return 401 without SIWE authentication', async () => {
      await request(app.getHttpServer())
        .post('/chest/store')
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address],
        })
        .expect(401);

      expect(fs.existsSync(chestPath)).toBe(false);
    });

    it('should return 401 with invalid SIWE signature', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      const headers = await siweHeaders(wallet);

      await request(app.getHttpServer())
        .post('/chest/store')
        .set({ ...headers, 'x-siwe-signature': '0x' + '00'.repeat(65) })
        .send({
          secret: createMockEncryptedPayload(),
          publicAddresses: [wallet.address],
        })
        .expect(401);

      consoleErrorSpy.mockRestore();
      expect(fs.existsSync(chestPath)).toBe(false);
    });

    it('should return 403 when caller is not among publicAddresses', async () => {
      const res = await storeAs(wallet2, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [wallet.address],
      });

      expect(res.status).toBe(403);
      expect(fs.existsSync(chestPath)).toBe(false);
    });

    it('should match caller against publicAddresses case-insensitively', async () => {
      const res = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [wallet.address.toLowerCase()],
      });

      expect(res.status).toBe(201);
    });

    it('should reject invalid encrypted payload', async () => {
      const res = await storeAs(wallet, {
        secret: { recipients: [] },
        publicAddresses: [wallet.address],
      });

      expect(res.status).toBe(400);
    });

    it('should reject empty publicAddresses array', async () => {
      const res = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [],
      });

      expect(res.status).toBe(400);
    });

    it('should reject invalid Ethereum address', async () => {
      const res = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [wallet.address, 'invalid-address'],
      });

      expect(res.status).toBe(400);
    });

    it('should reject malformed request (missing secret)', async () => {
      const res = await storeAs(wallet, {
        publicAddresses: [wallet.address],
      });

      expect(res.status).toBe(400);
    });

    it('should reject malformed request (missing publicAddresses)', async () => {
      const res = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
      });

      expect(res.status).toBe(400);
    });

    it('should accept checksummed addresses', async () => {
      const res = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [
          wallet.address,
          '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
        ],
      });

      expect(res.status).toBe(201);
    });

    it('should create chest.json file if it does not exist', async () => {
      expect(fs.existsSync(chestPath)).toBe(false);

      const res = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [wallet.address],
      });

      expect(res.status).toBe(201);
      expect(fs.existsSync(chestPath)).toBe(true);
    });
  });

  describe('GET /chest/access/:slot', () => {
    let slot: string;
    let nonce: string;

    beforeEach(async () => {
      // Store a secret first
      const storeResponse = await storeAs(wallet, {
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
        .expect('Cache-Control', 'no-store')
        .expect('Pragma', 'no-cache')
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

    it('should answer a non-owner like a non-existent slot', async () => {
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
        .expect(404, {
          statusCode: 404,
          error: 'Not Found',
          message: 'Slot not found',
        });
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
        .expect('Cache-Control', 'no-store')
        .expect(404, {
          statusCode: 404,
          error: 'Not Found',
          message: 'Slot not found',
        });
    });

    it('should allow multiple owners to access the same secret', async () => {
      // Store a secret with multiple owners
      const storeResponse = await storeAs(wallet, {
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
      const storeResponse = await storeAs(wallet, {
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
      const storeResponse = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [wallet.address],
      });
      expect(storeResponse.status).toBe(201);

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
      const store1Response = await storeAs(wallet, {
        secret: createMockEncryptedPayload(),
        publicAddresses: [wallet.address],
      });

      const slot1 = (store1Response.body as { slot: string }).slot;

      // Store second secret for wallet2
      const store2Response = await storeAs(wallet2, {
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
        .expect(404);
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
          expect(res.body).toHaveProperty('measurements');
          expect(res.body).toHaveProperty('eventLog');
          expect(res.body).toHaveProperty('timestamp');
          expect(['intel-tdx', 'none']).toContain(
            (res.body as { platform: string }).platform,
          );
        });
    });

    it('should return a placeholder without measurements outside a TEE', () => {
      return request(app.getHttpServer())
        .get('/chest/attestation')
        .expect(200)
        .expect((res) => {
          expect((res.body as { platform: string }).platform).toBe('none');
          expect(
            (res.body as { measurements: unknown }).measurements,
          ).toBeNull();
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

    it('should commit report_data to the keys and the nonce', () => {
      const nonce = 'cd'.repeat(32);
      return request(app.getHttpServer())
        .get(`/chest/attestation?nonce=${nonce}`)
        .expect(200)
        .expect((res) => {
          const body = res.body as { reportData: string };
          const expected = buildReportData(
            {
              mlkemPublicKey: new Uint8Array(1568).fill(0x01),
              relayer: new Uint8Array(20).fill(0x55),
              identityPublicKey: new Uint8Array(65).fill(0x04),
              tlsCertificateDer: new Uint8Array([0x30, 0x03]),
            },
            Buffer.from(nonce, 'hex'),
          );
          expect(body.reportData).toBe(`0x${expected.toString('hex')}`);
          expect(res.body).toHaveProperty('tlsCertificate', 'MAM=');
          expect(res.body).toHaveProperty('keyManifest.manifest.appId');
          expect(res.body).toHaveProperty('identitySignatureChain', ['0xaa']);
          expect(res.body).toHaveProperty(
            'relayerAddress',
            '0x' + '55'.repeat(20),
          );
          expect(res.body).toHaveProperty('relayerSignatureChain', ['0xbb']);
        });
    });

    it('should reject an invalid nonce', () => {
      return request(app.getHttpServer())
        .get('/chest/attestation?nonce=abcd')
        .expect(400);
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
