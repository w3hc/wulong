import { plainToInstance } from 'class-transformer';
import {
  IsEnum,
  IsInt,
  IsString,
  IsUrl,
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

  @IsUrl({ require_tld: false })
  KMS_URL?: string;

  // Rate limit window, in milliseconds
  @IsInt()
  @Min(1)
  THROTTLE_TTL?: number;

  // Requests allowed per IP within the window
  @IsInt()
  @Min(1)
  THROTTLE_LIMIT?: number;

  // Path of the chest file, defaults to <cwd>/chest.json
  @IsString()
  CHEST_PATH?: string;

  // Maximum size of chest.json, in bytes
  @IsInt()
  @Min(1)
  CHEST_MAX_BYTES?: number;
}

/**
 * Validates environment variables on application startup.
 * Fails fast if any required variables are missing or invalid.
 */
export function validateEnvironment(config: Record<string, unknown>) {
  const validatedConfig = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: true,
  });

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
  }

  return validatedConfig;
}

// Key material in env is readable by whoever deploys; the simulator's root is public
function isForbiddenInProduction(name: string): boolean {
  return (
    name.startsWith('ADMIN_MLKEM_') ||
    name === 'DSTACK_SIMULATOR_ENDPOINT' ||
    /(PRIVATE_KEY|MNEMONIC|SEED)$/i.test(name)
  );
}
