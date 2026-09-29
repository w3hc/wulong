import { INestApplication } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';

/**
 * Parses CORS_ORIGINS, a comma-separated list of origins such as
 * https://app.example.com. Unset or empty allows no cross-origin caller.
 */
export function parseCorsOrigins(value: string | undefined): string[] {
  const origins = (value ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  for (const origin of origins) {
    let parsed: URL | undefined;
    try {
      parsed = new URL(origin);
    } catch {
      parsed = undefined;
    }
    if (!parsed || parsed.origin !== origin) {
      throw new Error(
        `Invalid CORS_ORIGINS entry "${origin}": expected scheme://host[:port]`,
      );
    }
  }

  return origins;
}

// Auth travels in the SIWE headers, never in cookies, so no credentials mode
export function configureCors(app: INestApplication, origins: string[]): void {
  app.enableCors({
    origin: origins,
    allowedHeaders: ['Content-Type', 'X-SIWE-Message', 'X-SIWE-Signature'],
  });
}

// Only a TLS-terminating proxy (the ALLOW_TLS_OUTSIDE_ENCLAVE opt-out) sets
// X-Forwarded-For; with passthrough, clients could forge it to dodge rate limits.
// One hop: the proxy appends the peer address, earlier entries are client-supplied
export function configureTrustProxy(
  app: NestExpressApplication,
  tlsInEnclave: boolean,
): void {
  if (!tlsInEnclave) {
    app.set('trust proxy', 1);
  }
}

// Express computes ETag while sending the body, after interceptors have run,
// so MetadataSanitizerInterceptor cannot strip it; it hashes the body besides
export function configureResponseHeaders(app: NestExpressApplication): void {
  app.set('etag', false);
}
