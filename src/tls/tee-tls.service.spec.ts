import { X509Certificate } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Logger } from '@nestjs/common';
import { DstackV1Client } from '../keys/dstack-v1.client';
import { TeeTlsService } from './tee-tls.service';

const TEST_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUzuMKC95UhS7znKI
AyselpPjMAaNJ5BBL6vTP42WeVKhRANCAATfTy9w6c7tzYiGkxI7/NHDl3JYmyc2
nHBZaYwKEVEJCpzXka6BNX0PL1iB3xb9ZV4VSUlwDiaQmziMf7+RGiBY
-----END PRIVATE KEY-----`;

const TEST_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIBhDCCASmgAwIBAgIUQKhCch4cCedvNFLRLYnLZI5uaiwwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLd3Vsb25nLXRlc3QwIBcNMjYwOTI5MTY0NjU2WhgPMjEyNjA5
MDUxNjQ2NTZaMBYxFDASBgNVBAMMC3d1bG9uZy10ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE308vcOnO7c2IhpMSO/zRw5dyWJsnNpxwWWmMChFRCQqc15Gu
gTV9Dy9Ygd8W/WVeFUlJcA4mkJs4jH+/kRogWKNTMFEwHQYDVR0OBBYEFC/8SlZH
KEg2r+1JC6sorZK40o2cMB8GA1UdIwQYMBaAFC/8SlZHKEg2r+1JC6sorZK40o2c
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAISqc4fhk0re+9m2
K+2VHo25+h0ACfPQWaoekB+xTvGrAiEAr8cEk4fd6A+CZiJIKRKBXKBa20jQi9PO
XbHSk+gVyuo=
-----END CERTIFICATE-----`;

describe('TeeTlsService', () => {
  const env = { ...process.env };
  const cwd = process.cwd();
  let tmpDir: string;
  let getTlsKey: jest.Mock;
  let service: TeeTlsService;
  let logError: jest.SpyInstance;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tee-tls-'));
    process.chdir(tmpDir);
    getTlsKey = jest.fn().mockResolvedValue({
      key: TEST_KEY,
      certificateChain: [TEST_CERTIFICATE, 'CA_PEM'],
      leafCertificateDer: new Uint8Array([1, 2, 3]),
    });
    service = new TeeTlsService({
      getTlsKey,
    } as unknown as DstackV1Client);
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
    logError = jest.spyOn(Logger.prototype, 'error').mockImplementation();
  });

  afterEach(() => {
    service.onModuleDestroy();
    process.env = { ...env };
    process.chdir(cwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    jest.restoreAllMocks();
  });

  describe('in production', () => {
    beforeEach(() => {
      process.env.NODE_ENV = 'production';
      process.env.TLS_ALT_NAMES = 'app-3000s.example.com, wulong.example.com';
    });

    it('serves the dstack-issued certificate and exposes its leaf', async () => {
      await service.onModuleInit();

      expect(getTlsKey).toHaveBeenCalledWith([
        'app-3000s.example.com',
        'wulong.example.com',
      ]);
      expect(service.getServerOptions()).toEqual({
        key: TEST_KEY,
        cert: `${TEST_CERTIFICATE}\nCA_PEM`,
      });
      expect(service.getLeafCertificateDer()).toEqual(
        new Uint8Array([1, 2, 3]),
      );
    });

    it('refuses to start when dstack cannot issue a certificate', async () => {
      getTlsKey.mockRejectedValue(new Error('socket unreachable'));

      await expect(service.onModuleInit()).rejects.toThrow(
        'ALLOW_TLS_OUTSIDE_ENCLAVE',
      );
    });

    it('refuses to start without TLS_ALT_NAMES', async () => {
      delete process.env.TLS_ALT_NAMES;

      await expect(service.onModuleInit()).rejects.toThrow('TLS_ALT_NAMES');
      expect(getTlsKey).not.toHaveBeenCalled();
    });

    it('serves plain HTTP only on the explicit opt-out, and says so loudly', async () => {
      process.env.ALLOW_TLS_OUTSIDE_ENCLAVE = 'true';

      await service.onModuleInit();

      expect(getTlsKey).not.toHaveBeenCalled();
      expect(service.getServerOptions()).toBeNull();
      expect(service.getLeafCertificateDer()).toBeNull();
      expect(logError).toHaveBeenCalledWith(
        expect.stringContaining('TLS terminates outside the enclave'),
      );
    });
  });

  describe('outside production', () => {
    it('uses the local self-signed certificate', async () => {
      fs.mkdirSync('secrets');
      fs.writeFileSync('secrets/tls.key', TEST_KEY);
      fs.writeFileSync('secrets/tls.cert', TEST_CERTIFICATE);

      await service.onModuleInit();

      expect(getTlsKey).not.toHaveBeenCalled();
      expect(service.getServerOptions()).not.toBeNull();
      expect(Buffer.from(service.getLeafCertificateDer()!)).toEqual(
        new X509Certificate(TEST_CERTIFICATE).raw,
      );
    });

    it('has no certificate when none is present', async () => {
      await service.onModuleInit();

      expect(service.getServerOptions()).toBeNull();
      expect(service.getLeafCertificateDer()).toBeNull();
    });
  });
});
