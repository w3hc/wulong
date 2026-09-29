import { X509Certificate } from 'crypto';
import * as fs from 'fs';
import { ServerOptions } from 'https';
import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { DstackV1Client } from '../keys/dstack-v1.client';

const DEV_KEY_PATH = './secrets/tls.key';
const DEV_CERT_PATH = './secrets/tls.cert';
const OPT_OUT_REMINDER_MS = 60_000;

const OPT_OUT_WARNING =
  'ALLOW_TLS_OUTSIDE_ENCLAVE is set: serving plain HTTP, TLS terminates outside the enclave ' +
  'and every decrypted secret crosses the gateway in clear. Never run this in production.';

/**
 * Terminates TLS inside the enclave.
 *
 * In production the key and certificate come from the dstack KMS (GetTlsKey):
 * the private key is generated inside the CVM and never leaves it, and the
 * leaf certificate is bound into the attestation's report_data, so a client
 * can pin it. The dstack gateway must run in TLS passthrough mode.
 *
 * Production refuses to start without it, unless ALLOW_TLS_OUTSIDE_ENCLAVE is
 * set, which serves plain HTTP behind a TLS-terminating proxy and is logged as
 * an error at boot and every minute.
 */
@Injectable()
export class TeeTlsService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(TeeTlsService.name);
  private serverOptions: ServerOptions | null = null;
  private leafCertificateDer: Uint8Array | null = null;
  private reminder: NodeJS.Timeout | null = null;

  constructor(private readonly dstack: DstackV1Client) {}

  async onModuleInit(): Promise<void> {
    if (process.env.NODE_ENV !== 'production') {
      this.loadDevCertificate();
      return;
    }

    if (isOptedOut()) {
      this.logger.error(OPT_OUT_WARNING);
      this.reminder = setInterval(
        () => this.logger.error(OPT_OUT_WARNING),
        OPT_OUT_REMINDER_MS,
      );
      this.reminder.unref();
      return;
    }

    const altNames = parseAltNames(process.env.TLS_ALT_NAMES);
    if (altNames.length === 0) {
      throw new Error(
        'TLS_ALT_NAMES is required in production: the gateway hostnames the enclave certificate is issued for',
      );
    }

    try {
      const tls = await this.dstack.getTlsKey(altNames);
      this.serverOptions = {
        key: tls.key,
        cert: tls.certificateChain.join('\n'),
      };
      this.leafCertificateDer = tls.leafCertificateDer;
    } catch (error) {
      throw new Error(
        'In-enclave TLS unavailable: dstack GetTlsKey failed. Set ALLOW_TLS_OUTSIDE_ENCLAVE=true only to knowingly serve plain HTTP',
        { cause: error },
      );
    }
    this.logger.log(`TLS terminates in the enclave for ${altNames.join(', ')}`);
  }

  onModuleDestroy(): void {
    if (this.reminder) {
      clearInterval(this.reminder);
    }
  }

  /** HTTPS options for the server, or null to serve plain HTTP. */
  getServerOptions(): ServerOptions | null {
    return this.serverOptions;
  }

  /** DER of the served leaf certificate, committed to by report_data. */
  getLeafCertificateDer(): Uint8Array | null {
    return this.leafCertificateDer;
  }

  private loadDevCertificate(): void {
    if (!fs.existsSync(DEV_KEY_PATH) || !fs.existsSync(DEV_CERT_PATH)) {
      return;
    }
    const cert = fs.readFileSync(DEV_CERT_PATH);
    this.serverOptions = { key: fs.readFileSync(DEV_KEY_PATH), cert };
    this.leafCertificateDer = new Uint8Array(new X509Certificate(cert).raw);
  }
}

function isOptedOut(): boolean {
  return process.env.ALLOW_TLS_OUTSIDE_ENCLAVE === 'true';
}

function parseAltNames(value?: string): string[] {
  return (value ?? '')
    .split(',')
    .map((name) => name.trim())
    .filter((name) => name.length > 0);
}
