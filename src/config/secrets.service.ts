import { Injectable, OnModuleInit, Logger, Inject } from '@nestjs/common';
import { TeePlatformService } from '../attestation/tee-platform.service';

/**
 * Manages application secrets, loading them from KMS in production
 * or from environment variables in development.
 *
 * In a TEE environment, this service fetches secrets from an external KMS
 * by proving the enclave's identity via attestation.
 */
@Injectable()
export class SecretsService implements OnModuleInit {
  private readonly logger = new Logger('SecretsService');
  private secrets: Map<string, string> = new Map();

  constructor(
    @Inject(TeePlatformService)
    private readonly teePlatform: TeePlatformService,
  ) {}

  async onModuleInit(): Promise<void> {
    if (process.env.NODE_ENV === 'production') {
      // In Phala Cloud TEE, encrypted secrets are injected as env vars
      // Only fetch from KMS if explicitly configured. Keys never come from
      // here: they are derived by KeyDerivationService.
      if (process.env.KMS_URL) {
        await this.loadFromKms();
      } else {
        // Load from environment (encrypted secrets in TEE)
        this.logger.log('Loading secrets from TEE environment variables');
        Object.entries(process.env).forEach(([key, value]) => {
          if (value !== undefined) {
            this.secrets.set(key, value);
          }
        });
      }
    } else {
      // Dev: fall back to process.env (never do this in production)
      this.logger.warn('DEV MODE: loading secrets from process.env');
      Object.entries(process.env).forEach(([key, value]) => {
        if (value !== undefined) {
          this.secrets.set(key, value);
        }
      });
    }
  }

  /**
   * Retrieves a secret by key.
   * @param key The secret key to retrieve
   * @returns The secret value
   * @throws Error if the secret is not found
   */
  get(key: string): string {
    const val = this.secrets.get(key);
    if (!val) throw new Error(`Secret "${key}" not found`);
    return val;
  }

  private async loadFromKms(): Promise<void> {
    const kmsUrl = process.env.KMS_URL;
    if (!kmsUrl) {
      throw new Error('KMS_URL environment variable is required in production');
    }

    const attestationReport = await this.getAttestationReport();

    const response = await fetch(kmsUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attestation: attestationReport }),
    });

    if (!response.ok) {
      throw new Error('KMS refused to release secrets — attestation failed');
    }

    const secretsData = (await response.json()) as Record<string, string>;
    Object.entries(secretsData).forEach(([key, value]) => {
      this.secrets.set(key, value);
    });
    this.logger.log('Secrets loaded from KMS');
  }

  private async getAttestationReport(): Promise<string> {
    const attestation = await this.teePlatform.generateAttestationReport();
    return attestation.report;
  }
}
