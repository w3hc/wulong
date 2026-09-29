import { plainToInstance } from 'class-transformer';
import { IsEnum, IsInt, IsUrl, Min, validateSync } from 'class-validator';

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

  return validatedConfig;
}
