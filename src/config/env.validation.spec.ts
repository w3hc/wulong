import 'reflect-metadata';
import { validateEnvironment, EnvironmentVariables } from './env.validation';

describe('Environment Validation', () => {
  describe('validateEnvironment', () => {
    it('should validate valid development environment', () => {
      const config = { NODE_ENV: 'development' };
      const result = validateEnvironment(config);

      expect(result).toBeInstanceOf(EnvironmentVariables);
      expect(result.NODE_ENV).toBe('development');
    });

    it('should validate valid production environment', () => {
      const config = { NODE_ENV: 'production' };
      const result = validateEnvironment(config);

      expect(result.NODE_ENV).toBe('production');
    });

    it('should validate valid test environment', () => {
      const config = { NODE_ENV: 'test' };
      const result = validateEnvironment(config);

      expect(result.NODE_ENV).toBe('test');
    });

    it('should throw error for invalid NODE_ENV', () => {
      const config = { NODE_ENV: 'invalid' };

      expect(() => validateEnvironment(config)).toThrow(
        'Environment validation failed',
      );
    });

    it('should validate valid KMS_URL', () => {
      const config = {
        NODE_ENV: 'development',
        KMS_URL: 'http://localhost:8080',
      };
      const result = validateEnvironment(config);

      expect(result.KMS_URL).toBe('http://localhost:8080');
    });

    it('should validate KMS_URL without TLD requirement', () => {
      const config = {
        NODE_ENV: 'development',
        KMS_URL: 'http://kms-service',
      };
      const result = validateEnvironment(config);

      expect(result.KMS_URL).toBe('http://kms-service');
    });

    it('should allow invalid KMS_URL when skipMissingProperties is true', () => {
      const config = {
        NODE_ENV: 'development',
        KMS_URL: 'not-a-url',
      };

      // This doesn't throw because skipMissingProperties is true
      // and the validation is lenient
      const result = validateEnvironment(config);
      expect(result).toBeDefined();
    });

    it('should use default NODE_ENV when not provided', () => {
      const config = {};
      const result = validateEnvironment(config);

      expect(result.NODE_ENV).toBe('development');
    });

    it('should allow missing KMS_URL', () => {
      const config = { NODE_ENV: 'production' };
      const result = validateEnvironment(config);

      expect(result.KMS_URL).toBeUndefined();
    });
  });

  describe('key material in production', () => {
    it.each([
      'ADMIN_MLKEM_PRIVATE_KEY',
      'ADMIN_MLKEM_PUBLIC_KEY',
      'DSTACK_SIMULATOR_ENDPOINT',
      'RELAYER_PRIVATE_KEY',
      'WALLET_MNEMONIC',
    ])('should reject %s', (name) => {
      const config = { NODE_ENV: 'production', [name]: 'x' };

      expect(() => validateEnvironment(config)).toThrow(
        `${name} must not be set in production`,
      );
    });

    it('should allow key material outside production', () => {
      const config = {
        NODE_ENV: 'development',
        ADMIN_MLKEM_PRIVATE_KEY: 'x',
        DSTACK_SIMULATOR_ENDPOINT: '/tmp/dstack.sock',
      };

      expect(() => validateEnvironment(config)).not.toThrow();
    });
  });
});
