import * as fs from 'fs';
import { DSTACK_SOCKET_PATH, DstackV1Client } from '../keys/dstack-v1.client';
import { TeePlatformService } from './tee-platform.service';
import {
  TDX_QUOTE_MRTD_OFFSET,
  TDX_QUOTE_REPORT_DATA_OFFSET,
} from './tdx-quote';

const quoteOver = (reportData: Buffer) => {
  const quote = Buffer.alloc(1024);
  quote.writeUInt16LE(4, 0);
  quote.fill(0x07, TDX_QUOTE_MRTD_OFFSET, TDX_QUOTE_MRTD_OFFSET + 48);
  reportData.copy(quote, TDX_QUOTE_REPORT_DATA_OFFSET);
  return new Uint8Array(quote);
};

jest.mock('fs', () => ({
  ...jest.requireActual<typeof fs>('fs'),
  existsSync: jest.fn(),
}));

describe('TeePlatformService', () => {
  const originalEnv = process.env.NODE_ENV;
  let socketExists: boolean;
  let dstack: { isSimulator: jest.Mock; getQuote: jest.Mock };

  const create = () =>
    new TeePlatformService(dstack as unknown as DstackV1Client);

  beforeEach(() => {
    socketExists = true;
    (fs.existsSync as jest.Mock).mockImplementation(
      (path) => path === DSTACK_SOCKET_PATH && socketExists,
    );
    dstack = {
      isSimulator: jest.fn().mockReturnValue(false),
      getQuote: jest.fn((reportData: Uint8Array) =>
        Promise.resolve({
          quote: quoteOver(Buffer.from(reportData)),
          eventLog: '[]',
        }),
      ),
    };
  });

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
    jest.restoreAllMocks();
  });

  describe('in production', () => {
    beforeEach(() => {
      process.env.NODE_ENV = 'production';
    });

    it('starts when the first quote succeeds', async () => {
      await expect(create().onModuleInit()).resolves.toBeUndefined();
      expect(dstack.getQuote).toHaveBeenCalledTimes(1);
    });

    it('refuses to start without the dstack socket', async () => {
      socketExists = false;

      await expect(create().onModuleInit()).rejects.toThrow(
        'refusing to run outside a TEE',
      );
      expect(dstack.getQuote).not.toHaveBeenCalled();
    });

    it('refuses to start with the simulator', async () => {
      dstack.isSimulator.mockReturnValue(true);

      await expect(create().onModuleInit()).rejects.toThrow(
        'DSTACK_SIMULATOR_ENDPOINT must not be set in production',
      );
    });

    it('refuses to start when the first quote fails', async () => {
      dstack.getQuote.mockRejectedValue(new Error('socket hang up'));

      await expect(create().onModuleInit()).rejects.toThrow(
        'The first TDX quote could not be generated',
      );
    });

    it('refuses to start when the first quote does not parse', async () => {
      dstack.getQuote.mockResolvedValue({
        quote: new Uint8Array(10),
        eventLog: '[]',
      });

      await expect(create().onModuleInit()).rejects.toThrow(
        'The first TDX quote could not be generated',
      );
    });
  });

  describe('outside production', () => {
    beforeEach(() => {
      process.env.NODE_ENV = 'test';
    });

    it('returns a placeholder without the socket or the simulator', async () => {
      socketExists = false;
      const service = create();

      await expect(service.onModuleInit()).resolves.toBeUndefined();
      const report = await service.generateAttestationReport();

      expect(report.platform).toBe('none');
      expect(report.measurements).toBeNull();
      expect(report.eventLog).toBeNull();
      expect(dstack.getQuote).not.toHaveBeenCalled();
    });

    it('quotes through the simulator when it is configured', async () => {
      socketExists = false;
      dstack.isSimulator.mockReturnValue(true);

      const report = await create().generateAttestationReport();

      expect(report.platform).toBe('intel-tdx');
      expect(dstack.getQuote).toHaveBeenCalled();
    });
  });

  describe('generateAttestationReport', () => {
    it('returns the quote, its measurements and the event log', async () => {
      const reportData = Buffer.alloc(64, 0xab);

      const report = await create().generateAttestationReport(reportData);

      expect(dstack.getQuote).toHaveBeenCalledWith(reportData);
      expect(report.platform).toBe('intel-tdx');
      expect(Buffer.from(report.report, 'base64')).toEqual(
        Buffer.from(quoteOver(reportData)),
      );
      expect(report.measurements?.mrtd).toBe('07'.repeat(48));
      expect(report.measurements?.rtmr3).toBe('00'.repeat(48));
      expect(report.eventLog).toBe('[]');
    });

    it('accepts report_data shorter than 64 bytes, zero-padded', async () => {
      await expect(
        create().generateAttestationReport(Buffer.from([1, 2, 3])),
      ).resolves.toHaveProperty('platform', 'intel-tdx');
    });

    it('rejects a quote over different report_data', async () => {
      dstack.getQuote.mockResolvedValue({
        quote: quoteOver(Buffer.alloc(64, 0xff)),
        eventLog: '[]',
      });

      await expect(
        create().generateAttestationReport(Buffer.alloc(64, 0xab)),
      ).rejects.toThrow('does not carry the requested report_data');
    });
  });
});
