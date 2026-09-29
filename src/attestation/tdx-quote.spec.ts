import {
  TDX_QUOTE_MRTD_OFFSET,
  TDX_QUOTE_REPORT_DATA_OFFSET,
  TDX_QUOTE_RTMR_OFFSETS,
  parseTdxQuote,
} from './tdx-quote';

// Every field of a v4 quote, header included, filled with its own byte, so a
// read at the wrong offset returns the wrong pattern.
const FIELDS: [offset: number, length: number, fill: number][] = [
  [0, 48, 0x00], // header
  [48, 16, 0x01], // TEE_TCB_SVN
  [64, 48, 0x02], // MRSEAM
  [112, 48, 0x03], // MRSIGNERSEAM
  [160, 8, 0x04], // SEAMATTRIBUTES
  [168, 8, 0x05], // TDATTRIBUTES
  [176, 8, 0x06], // XFAM
  [184, 48, 0x07], // MRTD
  [232, 48, 0x08], // MRCONFIGID
  [280, 48, 0x09], // MROWNER
  [328, 48, 0x0a], // MROWNERCONFIG
  [376, 48, 0x0b], // RTMR0
  [424, 48, 0x0c], // RTMR1
  [472, 48, 0x0d], // RTMR2
  [520, 48, 0x0e], // RTMR3
  [568, 64, 0x0f], // REPORTDATA
];

const quote = () => {
  const buffer = Buffer.alloc(1024, 0xff);
  for (const [offset, length, fill] of FIELDS) {
    buffer.fill(fill, offset, offset + length);
  }
  buffer.writeUInt16LE(4, 0);
  return buffer;
};

describe('parseTdxQuote', () => {
  it('uses the TD report body offsets', () => {
    expect(TDX_QUOTE_MRTD_OFFSET).toBe(184);
    expect(TDX_QUOTE_RTMR_OFFSETS).toEqual([376, 424, 472, 520]);
    expect(TDX_QUOTE_REPORT_DATA_OFFSET).toBe(568);
  });

  it('reads MRTD, RTMR0-3 and report data from their fields', () => {
    const { measurements, reportData } = parseTdxQuote(quote());

    expect(measurements).toEqual({
      mrtd: '07'.repeat(48),
      rtmr0: '0b'.repeat(48),
      rtmr1: '0c'.repeat(48),
      rtmr2: '0d'.repeat(48),
      rtmr3: '0e'.repeat(48),
    });
    expect(reportData).toEqual(Buffer.alloc(64, 0x0f));
  });

  it('does not read MRSIGNERSEAM as MRTD', () => {
    expect(parseTdxQuote(quote()).measurements.mrtd).not.toBe('03'.repeat(48));
  });

  it('rejects a truncated quote', () => {
    expect(() => parseTdxQuote(quote().subarray(0, 600))).toThrow('too short');
  });

  it('rejects a quote that is not version 4', () => {
    const v5 = quote();
    v5.writeUInt16LE(5, 0);

    expect(() => parseTdxQuote(v5)).toThrow('version 5');
  });
});
