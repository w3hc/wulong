import { Test, TestingModule } from '@nestjs/testing';
import { SiweService } from './siwe.service';
import { SiweMessage } from 'siwe';
import { createHmac } from 'crypto';
import { Wallet } from 'ethers';
import { KeyDerivationService } from '../keys/key-derivation.service';

const ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

const noKeys = {
  isAvailable: () => false,
} as unknown as KeyDerivationService;

const derivedKeys = (key: string) =>
  ({
    isAvailable: () => true,
    macSiweNonce: (data: Uint8Array) =>
      createHmac('sha256', key).update(data).digest(),
  }) as unknown as KeyDerivationService;

describe('SiweService', () => {
  let service: SiweService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SiweService,
        { provide: KeyDerivationService, useValue: noKeys },
      ],
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
      expect(nonce).toHaveLength(64);
    });

    it('should generate unique nonces', () => {
      const nonce1 = service.generateNonce(ADDRESS);
      const nonce2 = service.generateNonce(ADDRESS);
      expect(nonce1).not.toBe(nonce2);
    });

    it('should store nothing until the nonce is used', () => {
      service.generateNonce(ADDRESS);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      expect(((service as any).used as Map<string, number>).size).toBe(0);
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
      const now = Date.now();
      const clock = jest
        .spyOn(Date, 'now')
        .mockReturnValue(now - 6 * 60 * 1000);
      const nonce = service.generateNonce(ADDRESS);
      clock.mockRestore();

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

    it('should reject a tampered nonce', async () => {
      const nonce = service.generateNonce(ADDRESS);
      const last = nonce.at(-1) === '0' ? '1' : '0';
      const { message, signature } = await signed({
        nonce: nonce.slice(0, -1) + last,
      });
      expect(await service.verifySignature(message, signature)).toBeNull();
    });

    it('should reject a nonce with a forged issue time', async () => {
      const nonce = service.generateNonce(ADDRESS);
      const later = (BigInt(`0x${nonce.slice(0, 16)}`) + 1n)
        .toString(16)
        .padStart(16, '0');
      const { message, signature } = await signed({
        nonce: later + nonce.slice(16),
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
      expect(() => new SiweService(noKeys)).toThrow('SIWE_DOMAIN');
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
      const custom = new SiweService(noKeys);

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
      expect(await signHttp(new SiweService(noKeys))).toBe(wallet.address);

      process.env.NODE_ENV = 'production';
      expect(await signHttp(new SiweService(noKeys))).toBeNull();
    });

    it('should accept https or no scheme in production', async () => {
      process.env.NODE_ENV = 'production';
      process.env.SIWE_DOMAIN = 'app.example';
      const custom = new SiweService(noKeys);

      expect(await signIn(custom, 'app.example')).toBe(true);
    });

    it('should default to localhost with and without port 3000', async () => {
      delete process.env.SIWE_DOMAIN;
      const custom = new SiweService(noKeys);

      expect(await signIn(custom, 'localhost')).toBe(true);
      expect(await signIn(custom, 'localhost:3000')).toBe(true);
      expect(await signIn(custom, 'localhost:4000')).toBe(false);
    });
  });

  describe('stateless nonces', () => {
    const signIn = async (siwe: SiweService, issuer = siwe) => {
      const wallet = Wallet.createRandom();
      const message = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'https://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: issuer.generateNonce(wallet.address),
        issuedAt: new Date().toISOString(),
      }).prepareMessage();
      const signature = await wallet.signMessage(message);
      return (
        (await siwe.verifySignature(message, signature)) === wallet.address
      );
    };

    it('should keep issuing nonces however many are pending', async () => {
      for (let i = 0; i < 20_000; i++) {
        service.generateNonce(Wallet.createRandom().address);
      }

      expect(await signIn(service)).toBe(true);
    });

    it('should verify nonces across instances sharing the derived key', async () => {
      const keys = derivedKeys('k');

      expect(await signIn(new SiweService(keys), new SiweService(keys))).toBe(
        true,
      );
      expect(
        await signIn(
          new SiweService(derivedKeys('other')),
          new SiweService(keys),
        ),
      ).toBe(false);
    });

    it('should not accept nonces from another fallback key', async () => {
      expect(await signIn(service, new SiweService(noKeys))).toBe(false);
    });

    it('should forget used nonces once they expire', async () => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const used = (service as any).used as Map<string, number>;
      expect(await signIn(service)).toBe(true);
      expect(used.size).toBe(1);

      const clock = jest
        .spyOn(Date, 'now')
        .mockReturnValue(Date.now() + 6 * 60 * 1000);
      const wallet = Wallet.createRandom();
      const message = new SiweMessage({
        domain: 'localhost',
        address: wallet.address,
        uri: 'https://localhost:3000',
        version: '1',
        chainId: 1,
        nonce: service.generateNonce(wallet.address),
        issuedAt: new Date(Date.now()).toISOString(),
      }).prepareMessage();
      await service.verifySignature(message, await wallet.signMessage(message));
      clock.mockRestore();

      expect(used.size).toBe(1);
    });
  });
});
