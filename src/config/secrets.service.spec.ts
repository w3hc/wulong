import { Test, TestingModule } from '@nestjs/testing';
import { SecretsService } from './secrets.service';
import { TeePlatformService } from '../attestation/tee-platform.service';

// Mock fetch globally
global.fetch = jest.fn();

describe('SecretsService', () => {
  let service: SecretsService;
  let teePlatformService: TeePlatformService;
  const originalEnv = process.env;

  beforeEach(async () => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecretsService,
        {
          provide: TeePlatformService,
          useValue: {
            generateAttestationReport: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<SecretsService>(SecretsService);
    teePlatformService = module.get<TeePlatformService>(TeePlatformService);

    // Prevent onModuleInit from auto-running in tests
    jest.spyOn(service, 'onModuleInit').mockResolvedValue(undefined);
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('onModuleInit - development mode', () => {
    it('should load secrets from environment variables in dev mode', async () => {
      process.env.NODE_ENV = 'development';
      process.env.TEST_SECRET = 'test-value';
      process.env.ANOTHER_SECRET = 'another-value';

      // Call the real implementation
      jest.spyOn(service, 'onModuleInit').mockRestore();
      await service.onModuleInit();

      expect(service.get('TEST_SECRET')).toBe('test-value');
      expect(service.get('ANOTHER_SECRET')).toBe('another-value');
    });

    it('should not load undefined environment variables', async () => {
      process.env.NODE_ENV = 'development';
      process.env.DEFINED_VAR = 'value';

      jest.spyOn(service, 'onModuleInit').mockRestore();
      await service.onModuleInit();

      expect(service.get('DEFINED_VAR')).toBe('value');
      expect(() => service.get('UNDEFINED_VAR')).toThrow(
        'Secret "UNDEFINED_VAR" not found',
      );
    });
  });

  describe('onModuleInit - production mode', () => {
    it('should load secrets from KMS in production', async () => {
      process.env.NODE_ENV = 'production';
      process.env.KMS_URL = 'https://kms.example.com/secrets';

      const mockAttestationReport = {
        platform: 'amd-sev-snp' as const,
        report: 'mock-attestation-report',
        measurement: 'mock-measurement',
        timestamp: '2026-03-17T00:00:00.000Z',
      };

      jest
        .spyOn(teePlatformService, 'generateAttestationReport')
        .mockResolvedValue(mockAttestationReport);

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({
          DATABASE_URL: 'postgres://prod-db',
          API_KEY: 'secret-api-key',
        }),
      });

      jest.spyOn(service, 'onModuleInit').mockRestore();
      await service.onModuleInit();

      expect(
        jest
          .spyOn(teePlatformService, 'generateAttestationReport')
          .getMockImplementation(),
      ).toBeDefined();
      expect(global.fetch).toHaveBeenCalledWith(
        'https://kms.example.com/secrets',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            attestation: 'mock-attestation-report',
          }),
        },
      );
      expect(service.get('DATABASE_URL')).toBe('postgres://prod-db');
      expect(service.get('API_KEY')).toBe('secret-api-key');
    });

    it('should load from environment variables when KMS_URL is not set in production', async () => {
      process.env.NODE_ENV = 'production';
      delete process.env.KMS_URL;
      process.env.TEST_SECRET = 'prod-env-value';

      jest.spyOn(service, 'onModuleInit').mockRestore();

      await service.onModuleInit();

      expect(service.get('TEST_SECRET')).toBe('prod-env-value');
    });

    it('should not skip KMS when ADMIN_MLKEM_PUBLIC_KEY is set', async () => {
      process.env.NODE_ENV = 'production';
      process.env.KMS_URL = 'https://kms.example.com/secrets';
      process.env.ADMIN_MLKEM_PUBLIC_KEY = 'mock-public-key';

      jest
        .spyOn(teePlatformService, 'generateAttestationReport')
        .mockResolvedValue({
          platform: 'intel-tdx',
          report: 'mock-report',
          measurement: 'mock-measurement',
          timestamp: '2026-03-17T00:00:00.000Z',
        });
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ API_KEY: 'from-kms' }),
      });

      jest.spyOn(service, 'onModuleInit').mockRestore();
      await service.onModuleInit();

      expect(global.fetch).toHaveBeenCalled();
      expect(service.get('API_KEY')).toBe('from-kms');
    });

    it('should throw error if KMS refuses attestation', async () => {
      process.env.NODE_ENV = 'production';
      process.env.KMS_URL = 'https://kms.example.com/secrets';

      jest
        .spyOn(teePlatformService, 'generateAttestationReport')
        .mockResolvedValue({
          platform: 'none',
          report: 'mock-report',
          measurement: 'mock',
          timestamp: '2026-03-17T00:00:00.000Z',
        });

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 403,
      });

      jest.spyOn(service, 'onModuleInit').mockRestore();

      await expect(service.onModuleInit()).rejects.toThrow(
        'KMS refused to release secrets — attestation failed',
      );
    });
  });

  describe('get', () => {
    it('should return secret value if it exists', async () => {
      process.env.NODE_ENV = 'development';
      process.env.MY_SECRET = 'secret-value';

      jest.spyOn(service, 'onModuleInit').mockRestore();
      await service.onModuleInit();

      expect(service.get('MY_SECRET')).toBe('secret-value');
    });

    it('should throw error if secret does not exist', () => {
      expect(() => service.get('NON_EXISTENT')).toThrow(
        'Secret "NON_EXISTENT" not found',
      );
    });

    it('should handle multiple gets for same secret', async () => {
      process.env.NODE_ENV = 'development';
      process.env.REPEATED_SECRET = 'value';

      jest.spyOn(service, 'onModuleInit').mockRestore();
      await service.onModuleInit();

      expect(service.get('REPEATED_SECRET')).toBe('value');
      expect(service.get('REPEATED_SECRET')).toBe('value');
      expect(service.get('REPEATED_SECRET')).toBe('value');
    });
  });
});
