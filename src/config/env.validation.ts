import { plainToInstance } from 'class-transformer';
import {
  IsEthereumAddress,
  IsEnum,
  IsIn,
  IsInt,
  IsNumberString,
  IsOptional,
  IsString,
  IsUrl,
  Matches,
  Min,
  validateSync,
} from 'class-validator';

/**
 * Environment configuration schema.
 * All required environment variables must be defined here and validated on startup.
 */
export class EnvironmentVariables {
  @IsEnum(['development', 'production', 'test'])
  NODE_ENV: 'development' | 'production' | 'test' = 'development';

  // Rate limit window, in milliseconds
  @IsOptional()
  @IsInt()
  @Min(1)
  THROTTLE_TTL?: number;

  // Requests allowed per IP within the window
  @IsOptional()
  @IsInt()
  @Min(1)
  THROTTLE_LIMIT?: number;

  // Path of the chest file, defaults to <cwd>/chest.json
  @IsOptional()
  @IsString()
  CHEST_PATH?: string;

  // Maximum size of chest.json, in bytes
  @IsOptional()
  @IsInt()
  @Min(1)
  CHEST_MAX_BYTES?: number;

  // Bytes of chest entries each address may store, defaults to 1 MiB
  @IsOptional()
  @IsInt()
  @Min(1)
  CHEST_ADDRESS_QUOTA_BYTES?: number;

  // Gateway hostnames the in-enclave TLS certificate is issued for, comma-separated
  @IsOptional()
  @IsString()
  TLS_ALT_NAMES?: string;

  // Hosts (with port) of the UIs allowed to request a SIWE signature, comma-separated
  @IsOptional()
  @IsString()
  SIWE_DOMAIN?: string;

  // Chain ids a SIWE message may name, comma-separated; defaults to 1,8453
  @IsOptional()
  @Matches(/^\s*\d+\s*(,\s*\d+\s*)*$/, {
    message: 'SIWE_CHAIN_IDS must be a comma-separated list of chain ids',
  })
  SIWE_CHAIN_IDS?: string;

  // Browser origins allowed to call the API, comma-separated; unset allows none
  @IsOptional()
  @IsString()
  CORS_ORIGINS?: string;

  // Serve plain HTTP behind a TLS-terminating proxy; secrets then leave the enclave in clear
  @IsOptional()
  @IsIn(['true', 'false'])
  ALLOW_TLS_OUTSIDE_ENCLAVE?: string;

  // Base JSON-RPC endpoint the relayer reads and sends through
  @IsOptional()
  @IsUrl({ require_tld: false, protocols: ['http', 'https'] })
  BASE_RPC_URL?: string;

  // WulongAnchor contract the relayer anchors the chest to; unset disables rollback protection
  @IsOptional()
  @IsEthereumAddress()
  WULONG_ANCHOR_ADDRESS?: string;

  // Relayer balance above which a warning is logged, in wei
  @IsOptional()
  @IsNumberString({ no_symbols: true })
  RELAYER_MAX_BALANCE_WEI?: string;
}

/**
 * Validates environment variables on application startup.
 * Fails fast if any required variables are missing or invalid.
 */
export function validateEnvironment(config: Record<string, unknown>) {
  const validatedConfig = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig);

  if (errors.length > 0) {
    throw new Error(
      `Environment validation failed:\n${errors.map((e) => Object.values(e.constraints || {}).join(', ')).join('\n')}`,
    );
  }

  if (validatedConfig.NODE_ENV === 'production') {
    const forbidden = Object.keys(config).filter(isForbiddenInProduction);
    if (forbidden.length > 0) {
      throw new Error(
        `Environment validation failed: ${forbidden.join(', ')} must not be set in production. Keys are derived inside the enclave, see docs/KEY_DERIVATION.md`,
      );
    }

    const missing = requiredInProduction(validatedConfig).filter(
      (name) => !hasEntries(validatedConfig[name]),
    );
    if (missing.length > 0) {
      throw new Error(
        `Environment validation failed: ${missing.join(', ')} must be set in production`,
      );
    }
  }

  return validatedConfig;
}

// The dstack endpoint is not listed: production always uses the socket, and
// key derivation aborts startup when it cannot reach it
function requiredInProduction(
  config: EnvironmentVariables,
): ('SIWE_DOMAIN' | 'TLS_ALT_NAMES' | 'BASE_RPC_URL')[] {
  return [
    'SIWE_DOMAIN' as const,
    ...(config.ALLOW_TLS_OUTSIDE_ENCLAVE === 'true'
      ? []
      : ['TLS_ALT_NAMES' as const]),
    ...(config.WULONG_ANCHOR_ADDRESS ? ['BASE_RPC_URL' as const] : []),
  ];
}

// Comma-separated lists count as set only if they hold at least one entry
function hasEntries(value?: string): boolean {
  return (value ?? '').split(',').some((entry) => entry.trim() !== '');
}

// Key material in env is readable by whoever deploys; the simulator's root is public
function isForbiddenInProduction(name: string): boolean {
  return (
    name.startsWith('ADMIN_MLKEM_') ||
    name === 'DSTACK_SIMULATOR_ENDPOINT' ||
    /(PRIVATE_KEY|MNEMONIC|SEED)$/i.test(name)
  );
}
