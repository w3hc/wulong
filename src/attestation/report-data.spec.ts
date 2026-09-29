import { buildReportData, parseNonce } from './report-data';

// Vectors computed independently in Python with hashlib and struct.pack('>I')
const EK = new Uint8Array(1568).fill(0x01);
const IDENTITY = new Uint8Array([0x04, ...new Uint8Array(64).fill(0x02)]);
const RELAYER = new Uint8Array(20).fill(0xab);
const CERT = Buffer.from('cert');

describe('buildReportData', () => {
  it('commits to the ML-KEM key alone, with empty terms and a zero nonce', () => {
    const reportData = buildReportData({ mlkemPublicKey: EK });

    expect(reportData).toHaveLength(64);
    expect(reportData.subarray(0, 32).toString('hex')).toBe(
      'ab74ab2928270b91ee58b51f514cf4236237c91e9c0ece50229482c2415b2730',
    );
    expect(reportData.subarray(32).equals(Buffer.alloc(32))).toBe(true);
  });

  it('commits to every key and the certificate hash', () => {
    const reportData = buildReportData({
      mlkemPublicKey: EK,
      relayer: RELAYER,
      identityPublicKey: IDENTITY,
      tlsCertificateDer: CERT,
    });

    expect(reportData.subarray(0, 32).toString('hex')).toBe(
      'fbc49c05b051e0bf7c29e5a85931d4c84fba51aaefc771ba9a067e7afff31b3c',
    );
  });

  it('places the nonce in the second half', () => {
    const nonce = Buffer.alloc(32, 0x7f);

    const reportData = buildReportData({ mlkemPublicKey: EK }, nonce);

    expect(reportData.subarray(32).equals(nonce)).toBe(true);
  });

  it('changes the commitment when the key changes', () => {
    const other = new Uint8Array(1568).fill(0x02);

    expect(
      buildReportData({ mlkemPublicKey: EK })
        .subarray(0, 32)
        .equals(buildReportData({ mlkemPublicKey: other }).subarray(0, 32)),
    ).toBe(false);
  });

  it('rejects a nonce that is not 32 bytes', () => {
    expect(() =>
      buildReportData({ mlkemPublicKey: EK }, Buffer.alloc(16)),
    ).toThrow('Nonce must be 32 bytes');
  });
});

describe('parseNonce', () => {
  const hex = '11'.repeat(32);

  it('returns undefined when no nonce is sent', () => {
    expect(parseNonce(undefined)).toBeUndefined();
    expect(parseNonce('')).toBeUndefined();
  });

  it('parses 64 hex characters, with or without 0x', () => {
    expect(parseNonce(hex)).toEqual(Buffer.alloc(32, 0x11));
    expect(parseNonce(`0x${hex}`)).toEqual(Buffer.alloc(32, 0x11));
  });

  it.each(['11'.repeat(31), '11'.repeat(33), 'zz'.repeat(32)])(
    'rejects %s',
    (value) => {
      expect(() => parseNonce(value)).toThrow('Nonce must be 32 bytes of hex');
    },
  );
});
