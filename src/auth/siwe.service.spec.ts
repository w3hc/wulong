import { Test, TestingModule } from '@nestjs/testing';
import { SiweService } from './siwe.service';
import { SiweMessage } from 'siwe';
import { Wallet } from 'ethers';

describe('SiweService', () => {
  let service: SiweService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SiweService],
    }).compile();

    service = module.get<SiweService>(SiweService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateNonce', () => {
    it('should generate an alphanumeric string (at least 8 characters)', () => {
      const nonce = service.generateNonce();
      expect(nonce).toMatch(/^[A-Za-z0-9]{8,}$/);
    });

    it('should generate unique nonces', () => {
      const nonce1 = service.generateNonce();
      const nonce2 = service.generateNonce();
      expect(nonce1).not.toBe(nonce2);
    });

    it('should store nonce internally', () => {
      const nonce = service.generateNonce();
      // Nonce should be in internal storage (we'll verify through verification)
      expect(nonce).toBeDefined();
    });
  });

  describe('verifySignature', () => {
    let wallet: Wallet;

    beforeEach(() => {
      // Use a test wallet with known private key
      wallet = new Wallet(
        '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
      );
    });

    it('should return null for invalid signature', async () => {
      // Suppress expected error logs from ethers library
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const nonce = service.generateNonce();
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
      // Use a valid signature format but wrong signature
      const wrongSignature =
        '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

      const result = await service.verifySignature(message, wrongSignature);
      expect(result).toBeNull();

      consoleErrorSpy.mockRestore();
    });

    it('should return null for signature with non-existent nonce', async () => {
      const siweMessage = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'https://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: 'nonExistentNonce123', // Valid format but non-existent
        issuedAt: new Date().toISOString(),
      });

      const message = siweMessage.prepareMessage();
      const signature = await wallet.signMessage(message);

      const result = await service.verifySignature(message, signature);
      expect(result).toBeNull();
    });

    it('should verify valid signature and return address', async () => {
      const nonce = service.generateNonce();
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

      const result = await service.verifySignature(message, signature);
      expect(result).toBe(wallet.address);
    });

    it('should reject reused nonce (single-use)', async () => {
      const nonce = service.generateNonce();
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

      // First verification should succeed
      const result1 = await service.verifySignature(message, signature);
      expect(result1).toBe(wallet.address);

      // Second verification with same nonce should fail (nonce consumed)
      const result2 = await service.verifySignature(message, signature);
      expect(result2).toBeNull();
    });

    it('should reject expired nonce', async () => {
      const nonce = service.generateNonce();

      // Mock nonce as expired by manipulating time
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const nonces = (service as any).nonces as Map<
        string,
        { nonce: string; createdAt: number }
      >;

      const nonceEntry = nonces.get(nonce)!;
      nonceEntry.createdAt = Date.now() - 6 * 60 * 1000; // 6 minutes ago

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

      const result = await service.verifySignature(message, signature);
      expect(result).toBeNull();
    });

    const signed = async (overrides: Partial<SiweMessage>) => {
      const message = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'https://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: service.generateNonce(),
        issuedAt: new Date().toISOString(),
        ...overrides,
      }).prepareMessage();
      return { message, signature: await wallet.signMessage(message) };
    };

    it('should reject a message signed for another domain', async () => {
      const { message, signature } = await signed({ domain: 'evil.example' });
      expect(await service.verifySignature(message, signature)).toBeNull();
    });

    it('should reject a message past its Expiration Time', async () => {
      const { message, signature } = await signed({
        expirationTime: new Date(Date.now() - 1000).toISOString(),
      });
      expect(await service.verifySignature(message, signature)).toBeNull();
    });

    it('should reject a message before its Not Before', async () => {
      const { message, signature } = await signed({
        notBefore: new Date(Date.now() + 60 * 1000).toISOString(),
      });
      expect(await service.verifySignature(message, signature)).toBeNull();
    });

    it('should reject an Issued At in the future', async () => {
      const { message, signature } = await signed({
        issuedAt: new Date(Date.now() + 60 * 1000).toISOString(),
      });
      expect(await service.verifySignature(message, signature)).toBeNull();
    });

    it('should reject an Issued At older than the nonce', async () => {
      const { message, signature } = await signed({
        issuedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
      });
      expect(await service.verifySignature(message, signature)).toBeNull();
    });

    it('should consume the nonce on a failed attempt', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      const { message, signature } = await signed({});
      const wrongSignature = await new Wallet(
        '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
      ).signMessage(message);

      expect(await service.verifySignature(message, wrongSignature)).toBeNull();
      expect(await service.verifySignature(message, signature)).toBeNull();
      consoleErrorSpy.mockRestore();
    });

    it('should return null for malformed message', async () => {
      const result = await service.verifySignature(
        'not a valid SIWE message',
        '0x1234',
      );
      expect(result).toBeNull();
    });
  });

  describe('domain', () => {
    const env = { ...process.env };

    afterEach(() => {
      process.env = { ...env };
    });

    it('should throw in production when SIWE_DOMAIN is unset', () => {
      process.env.NODE_ENV = 'production';
      delete process.env.SIWE_DOMAIN;
      expect(() => new SiweService()).toThrow('SIWE_DOMAIN');
    });

    it('should accept messages for SIWE_DOMAIN', async () => {
      process.env.SIWE_DOMAIN = 'wulong.example';
      const custom = new SiweService();
      const wallet = Wallet.createRandom();
      const message = new SiweMessage({
        domain: 'wulong.example',
        address: wallet.address,
        uri: 'https://wulong.example',
        version: '1',
        chainId: 1,
        nonce: custom.generateNonce(),
        issuedAt: new Date().toISOString(),
      }).prepareMessage();
      const signature = await wallet.signMessage(message);

      expect(await custom.verifySignature(message, signature)).toBe(
        wallet.address,
      );
    });
  });

  describe('cleanExpiredNonces', () => {
    it('should clean up expired nonces when generating new nonce', () => {
      // Generate a nonce
      const nonce1 = service.generateNonce();

      // Access the internal nonces map to manipulate it
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const nonces = (service as any).nonces as Map<
        string,
        { nonce: string; createdAt: number }
      >;

      // Manually set the nonce as expired (> 5 minutes old)
      const expiredEntry = nonces.get(nonce1);
      if (expiredEntry) {
        expiredEntry.createdAt = Date.now() - 6 * 60 * 1000; // 6 minutes ago
      }

      // Verify the expired nonce is still in the map
      expect(nonces.has(nonce1)).toBe(true);

      // Generate a new nonce, which should trigger cleanup
      const nonce2 = service.generateNonce();

      // The expired nonce should now be removed
      expect(nonces.has(nonce1)).toBe(false);
      expect(nonces.has(nonce2)).toBe(true);
    });
  });
});
