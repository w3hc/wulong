import { Test, TestingModule } from '@nestjs/testing';
import { SiweService } from './siwe.service';
import { SiweMessage } from 'siwe';
import { Wallet } from 'ethers';

const ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

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
      const nonce = service.generateNonce(ADDRESS);
      expect(nonce).toMatch(/^[A-Za-z0-9]{8,}$/);
    });

    it('should generate unique nonces', () => {
      const nonce1 = service.generateNonce(ADDRESS);
      const nonce2 = service.generateNonce(ADDRESS);
      expect(nonce1).not.toBe(nonce2);
    });

    it('should store nonce internally', () => {
      const nonce = service.generateNonce(ADDRESS);
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

      const nonce = service.generateNonce(ADDRESS);
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
      const nonce = service.generateNonce(ADDRESS);
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
      const nonce = service.generateNonce(ADDRESS);
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
      const nonce = service.generateNonce(ADDRESS);

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
        nonce: service.generateNonce(ADDRESS),
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

    it('should reject a nonce issued to another address', async () => {
      const { message, signature } = await signed({
        nonce: service.generateNonce(Wallet.createRandom().address),
      });
      expect(await service.verifySignature(message, signature)).toBeNull();
    });

    it('should accept the address in any case', async () => {
      const { message, signature } = await signed({
        nonce: service.generateNonce(ADDRESS.toLowerCase()),
      });
      expect(await service.verifySignature(message, signature)).toBe(ADDRESS);
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

    const signIn = async (siwe: SiweService, domain: string) => {
      const wallet = Wallet.createRandom();
      const message = new SiweMessage({
        domain,
        address: wallet.address,
        uri: `https://${domain}`,
        version: '1',
        chainId: 1,
        nonce: siwe.generateNonce(wallet.address),
        issuedAt: new Date().toISOString(),
      }).prepareMessage();
      const signature = await wallet.signMessage(message);
      const result = await siwe.verifySignature(message, signature);
      return result === wallet.address;
    };

    it('should accept every host listed in SIWE_DOMAIN', async () => {
      process.env.SIWE_DOMAIN = 'app.example, other.example:8443';
      const custom = new SiweService();

      expect(await signIn(custom, 'app.example')).toBe(true);
      expect(await signIn(custom, 'other.example:8443')).toBe(true);
      expect(await signIn(custom, 'localhost')).toBe(false);
    });

    it('should accept http only outside production', async () => {
      process.env.SIWE_DOMAIN = 'app.example';
      const wallet = Wallet.createRandom();
      const signHttp = async (siwe: SiweService) => {
        const message = new SiweMessage({
          scheme: 'http',
          domain: 'app.example',
          address: wallet.address,
          uri: 'http://app.example',
          version: '1',
          chainId: 1,
          nonce: siwe.generateNonce(wallet.address),
          issuedAt: new Date().toISOString(),
        }).prepareMessage();
        const signature = await wallet.signMessage(message);
        return siwe.verifySignature(message, signature);
      };

      process.env.NODE_ENV = 'development';
      expect(await signHttp(new SiweService())).toBe(wallet.address);

      process.env.NODE_ENV = 'production';
      expect(await signHttp(new SiweService())).toBeNull();
    });

    it('should accept https or no scheme in production', async () => {
      process.env.NODE_ENV = 'production';
      process.env.SIWE_DOMAIN = 'app.example';
      const custom = new SiweService();

      expect(await signIn(custom, 'app.example')).toBe(true);
    });

    it('should default to localhost with and without port 3000', async () => {
      delete process.env.SIWE_DOMAIN;
      const custom = new SiweService();

      expect(await signIn(custom, 'localhost')).toBe(true);
      expect(await signIn(custom, 'localhost:3000')).toBe(true);
      expect(await signIn(custom, 'localhost:4000')).toBe(false);
    });
  });

  describe('cleanExpiredNonces', () => {
    it('should clean up expired nonces when generating new nonce', () => {
      // Generate a nonce
      const nonce1 = service.generateNonce(ADDRESS);

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
      const nonce2 = service.generateNonce(ADDRESS);

      // The expired nonce should now be removed
      expect(nonces.has(nonce1)).toBe(false);
      expect(nonces.has(nonce2)).toBe(true);
    });
  });

  describe('nonce cap', () => {
    const fill = (createdAt: number) => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const nonces = (service as any).nonces as Map<
        string,
        { nonce: string; address: string; createdAt: number }
      >;
      for (let i = 0; i < 10_000; i++) {
        nonces.set(`n${i}`, { nonce: `n${i}`, address: ADDRESS, createdAt });
      }
      return nonces;
    };

    it('should reject new nonces once the store is full', () => {
      const nonces = fill(Date.now());

      expect(() => service.generateNonce(ADDRESS)).toThrow(
        'Too many pending nonces',
      );
      expect(nonces.size).toBe(10_000);
      expect(nonces.has('n0')).toBe(true);
    });

    it('should accept new nonces once pending ones expire', () => {
      const nonces = fill(Date.now() - 6 * 60 * 1000);

      const nonce = service.generateNonce(ADDRESS);

      expect(nonces.size).toBe(1);
      expect(nonces.has(nonce)).toBe(true);
    });
  });
});
