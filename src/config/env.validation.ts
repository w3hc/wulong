import { plainToInstance } from 'class-transformer';
import {
  IsEnum,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
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

  // Gateway hostnames the in-enclave TLS certificate is issued for, comma-separated
  @IsOptional()
  @IsString()
  TLS_ALT_NAMES?: string;

  // Hosts (with port) of the UIs allowed to request a SIWE signature, comma-separated
  @IsOptional()
  @IsString()
  SIWE_DOMAIN?: string;

  // Browser origins allowed to call the API, comma-separated; unset allows none
  @IsOptional()
  @IsString()
  CORS_ORIGINS?: string;

  // Serve plain HTTP behind a TLS-terminating proxy; secrets then leave the enclave in clear
  @IsOptional()
  @IsIn(['true', 'false'])
  ALLOW_TLS_OUTSIDE_ENCLAVE?: string;
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
): ('SIWE_DOMAIN' | 'TLS_ALT_NAMES')[] {
  return config.ALLOW_TLS_OUTSIDE_ENCLAVE === 'true'
    ? ['SIWE_DOMAIN']
    : ['SIWE_DOMAIN', 'TLS_ALT_NAMES'];
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
