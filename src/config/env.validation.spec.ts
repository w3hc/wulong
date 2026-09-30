import 'reflect-metadata';
import { validateEnvironment, EnvironmentVariables } from './env.validation';

describe('Environment Validation', () => {
  const production = {
    NODE_ENV: 'production',
    SIWE_DOMAIN: 'app.example.com',
    TLS_ALT_NAMES: 'app-3000s.gateway.example.com',
  };

  describe('validateEnvironment', () => {
    it('should validate valid development environment', () => {
      const config = { NODE_ENV: 'development' };
      const result = validateEnvironment(config);

      expect(result).toBeInstanceOf(EnvironmentVariables);
      expect(result.NODE_ENV).toBe('development');
    });

    it('should validate valid production environment', () => {
      const result = validateEnvironment(production);

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

    it('should use default NODE_ENV when not provided', () => {
      const config = {};
      const result = validateEnvironment(config);

      expect(result.NODE_ENV).toBe('development');
    });
  });

  describe('SIWE_CHAIN_IDS', () => {
    it('should accept a comma-separated list of chain ids', () => {
      const result = validateEnvironment({
        NODE_ENV: 'test',
        SIWE_CHAIN_IDS: '1, 8453',
      });

      expect(result.SIWE_CHAIN_IDS).toBe('1, 8453');
    });

    it.each(['', 'base', '1,,8453', '0x2105'])('should reject %p', (value) => {
      expect(() =>
        validateEnvironment({ NODE_ENV: 'test', SIWE_CHAIN_IDS: value }),
      ).toThrow('SIWE_CHAIN_IDS must be a comma-separated list of chain ids');
    });
  });

  describe('relayer', () => {
    it.each([
      ['WULONG_ANCHOR_ADDRESS', '0x1234'],
      ['BASE_RPC_URL', 'not a url'],
      ['RELAYER_MAX_BALANCE_WEI', '-1'],
      ['RELAYER_MAX_BALANCE_WEI', '1e18'],
    ])('should reject an invalid %s (%s)', (name, value) => {
      expect(() =>
        validateEnvironment({ NODE_ENV: 'test', [name]: value }),
      ).toThrow('Environment validation failed');
    });

    it('should accept a relayer configuration', () => {
      expect(() =>
        validateEnvironment({
          NODE_ENV: 'test',
          BASE_RPC_URL: 'http://localhost:8545',
          WULONG_ANCHOR_ADDRESS: '0x' + '77'.repeat(20),
          RELAYER_MAX_BALANCE_WEI: '10000000000000000',
        }),
      ).not.toThrow();
    });
  });

  describe('required in production', () => {
    it.each(['SIWE_DOMAIN', 'TLS_ALT_NAMES'])(
      'should reject a missing %s',
      (name) => {
        const config = { ...production, [name]: undefined };

        expect(() => validateEnvironment(config)).toThrow(
          `${name} must be set in production`,
        );
      },
    );

    it('should reject a list with no entries', () => {
      const config = { ...production, SIWE_DOMAIN: ' , ' };

      expect(() => validateEnvironment(config)).toThrow(
        'SIWE_DOMAIN must be set in production',
      );
    });

    it('should not require TLS_ALT_NAMES when TLS is opted out', () => {
      const config = {
        NODE_ENV: 'production',
        SIWE_DOMAIN: 'app.example.com',
        ALLOW_TLS_OUTSIDE_ENCLAVE: 'true',
      };

      expect(() => validateEnvironment(config)).not.toThrow();
    });

    it('should require BASE_RPC_URL with an anchor address', () => {
      const config = {
        ...production,
        WULONG_ANCHOR_ADDRESS: '0x' + '77'.repeat(20),
      };

      expect(() => validateEnvironment(config)).toThrow(
        'BASE_RPC_URL must be set in production',
      );
      expect(() =>
        validateEnvironment({
          ...config,
          BASE_RPC_URL: 'https://mainnet.base.org',
        }),
      ).not.toThrow();
    });

    it('should not require them outside production', () => {
      expect(() => validateEnvironment({ NODE_ENV: 'test' })).not.toThrow();
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
