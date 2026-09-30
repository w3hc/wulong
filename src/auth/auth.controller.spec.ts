import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { SiweService } from './siwe.service';
import { KeyDerivationService } from '../keys/key-derivation.service';

const body = { address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' };

describe('AuthController', () => {
  let authController: AuthController;
  let siweService: SiweService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        SiweService,
        {
          provide: KeyDerivationService,
          useValue: { isAvailable: () => false },
        },
      ],
    }).compile();

    authController = module.get<AuthController>(AuthController);
    siweService = module.get<SiweService>(SiweService);
  });

  it('should be defined', () => {
    expect(authController).toBeDefined();
  });

  it('should have SiweService injected', () => {
    expect(siweService).toBeDefined();
  });

  describe('generateNonce', () => {
    it('should generate a nonce', () => {
      const result = authController.generateNonce(body);

      expect(result).toHaveProperty('nonce');
      expect(result).toHaveProperty('issuedAt');
      expect(result).toHaveProperty('expiresAt');
      expect(typeof result.nonce).toBe('string');
      expect(result.nonce.length).toBeGreaterThanOrEqual(8); // SIWE requires at least 8 alphanumeric characters
      expect(result.nonce).toMatch(/^[A-Za-z0-9]+$/); // Alphanumeric only
    });

    it('should generate unique nonces', () => {
      const nonce1 = authController.generateNonce(body);
      const nonce2 = authController.generateNonce(body);

      expect(nonce1.nonce).not.toBe(nonce2.nonce);
    });

    it('should set expiration to 5 minutes from issuedAt', () => {
      const result = authController.generateNonce(body);
      const issuedAt = new Date(result.issuedAt);
      const expiresAt = new Date(result.expiresAt);
      const diffMs = expiresAt.getTime() - issuedAt.getTime();

      expect(diffMs).toBeGreaterThanOrEqual(5 * 60 * 1000); // At least 5 minutes
      expect(diffMs).toBeLessThan(5 * 60 * 1000 + 10); // Allow small timing variance
    });
  });
});
