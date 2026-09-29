import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as fs from 'fs';
import { DSTACK_SOCKET_PATH, DstackV1Client } from '../keys/dstack-v1.client';
import { TdxMeasurements, parseTdxQuote } from './tdx-quote';

export interface AttestationReport {
  platform: 'intel-tdx' | 'none';
  /** Base64 TDX quote, or a base64 JSON placeholder when platform is none. */
  report: string;
  /** Null when platform is none. */
  measurements: TdxMeasurements | null;
  /** dstack event log (JSON), which replays RTMR0-3. Null when platform is none. */
  eventLog: string | null;
  timestamp: string;
}

/**
 * Produces TDX quotes through the dstack guest agent, the only supported TEE.
 *
 * In production it refuses to start without the dstack socket, with the
 * simulator, or when the first quote cannot be generated. Outside production,
 * with neither the socket nor DSTACK_SIMULATOR_ENDPOINT, it returns a
 * placeholder report with platform `none`.
 */
@Injectable()
export class TeePlatformService implements OnModuleInit {
  private readonly logger = new Logger(TeePlatformService.name);
  private readonly platform: AttestationReport['platform'];

  constructor(private readonly dstack: DstackV1Client) {
    this.platform =
      dstack.isSimulator() || fs.existsSync(DSTACK_SOCKET_PATH)
        ? 'intel-tdx'
        : 'none';
  }

  async onModuleInit(): Promise<void> {
    if (process.env.NODE_ENV !== 'production') {
      if (this.platform === 'none') {
        this.logger.warn(
          'No dstack guest agent: attestations are placeholders. Run the dstack simulator and set DSTACK_SIMULATOR_ENDPOINT.',
        );
      }
      return;
    }

    if (this.dstack.isSimulator()) {
      throw new Error(
        'DSTACK_SIMULATOR_ENDPOINT must not be set in production: its quotes prove nothing',
      );
    }
    if (this.platform === 'none') {
      throw new Error(
        `No dstack guest agent at ${DSTACK_SOCKET_PATH}: refusing to run outside a TEE`,
      );
    }
    try {
      await this.generateAttestationReport(Buffer.alloc(64));
    } catch (error) {
      throw new Error('The first TDX quote could not be generated', {
        cause: error,
      });
    }
  }

  /**
   * Generates a TDX quote whose report_data is `reportData`, zero-padded to
   * 64 bytes.
   * @param reportData At most 64 bytes; zeros when omitted
   * @returns The quote, its measurements and the event log
   * @throws Error if the quote fails, does not parse, or does not carry
   * `reportData`
   */
  async generateAttestationReport(
    reportData: Buffer = Buffer.alloc(64),
  ): Promise<AttestationReport> {
    const timestamp = new Date().toISOString();

    if (this.platform === 'none') {
      return {
        platform: 'none',
        report: Buffer.from(
          JSON.stringify({
            warning: 'NO_TEE_PLACEHOLDER_FOR_DEVELOPMENT_ONLY',
            timestamp,
          }),
        ).toString('base64'),
        measurements: null,
        eventLog: null,
        timestamp,
      };
    }

    const { quote, eventLog } = await this.dstack.getQuote(reportData);
    const parsed = parseTdxQuote(Buffer.from(quote));
    const expected = Buffer.alloc(64);
    reportData.copy(expected);
    if (!parsed.reportData.equals(expected)) {
      throw new Error('The TDX quote does not carry the requested report_data');
    }

    return {
      platform: 'intel-tdx',
      report: Buffer.from(quote).toString('base64'),
      measurements: parsed.measurements,
      eventLog,
      timestamp,
    };
  }
}
