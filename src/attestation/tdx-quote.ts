/**
 * Field offsets in a TDX v4 quote: a 48-byte header, then the TD report body.
 * See the Intel TDX DCAP Quote Generation Library and Quote Verification
 * Library spec, "TD Quote Body".
 */
const QUOTE_HEADER_LENGTH = 48;
const MEASUREMENT_LENGTH = 48;
const REPORT_DATA_LENGTH = 64;

export const TDX_QUOTE_MRTD_OFFSET = QUOTE_HEADER_LENGTH + 136;
export const TDX_QUOTE_RTMR_OFFSETS = [328, 376, 424, 472].map(
  (offset) => QUOTE_HEADER_LENGTH + offset,
);
export const TDX_QUOTE_REPORT_DATA_OFFSET = QUOTE_HEADER_LENGTH + 520;

const MIN_QUOTE_LENGTH = TDX_QUOTE_REPORT_DATA_OFFSET + REPORT_DATA_LENGTH;

/** Hex-encoded measurements, without a 0x prefix. */
export interface TdxMeasurements {
  /** The TD's initial memory: the dstack OS image firmware. */
  mrtd: string;
  /** Virtual hardware configuration. */
  rtmr0: string;
  /** Linux kernel. */
  rtmr1: string;
  /** Kernel command line and initrd. */
  rtmr2: string;
  /** Runtime events, including the app's compose hash: the app's identity. */
  rtmr3: string;
}

export interface TdxQuote {
  measurements: TdxMeasurements;
  reportData: Buffer;
}

/**
 * Reads the measurements and report data out of a TDX v4 quote. It does not
 * verify the quote signature.
 * @param quote The raw quote
 * @returns The measurements and the 64-byte report data
 * @throws Error if the quote is not a v4 TDX quote
 */
export function parseTdxQuote(quote: Buffer): TdxQuote {
  if (quote.length < MIN_QUOTE_LENGTH) {
    throw new Error(`TDX quote too short: ${quote.length} bytes`);
  }
  const version = quote.readUInt16LE(0);
  if (version !== 4) {
    throw new Error(`Unsupported TDX quote version ${version}`);
  }
  const measurement = (offset: number) =>
    quote.subarray(offset, offset + MEASUREMENT_LENGTH).toString('hex');
  const [rtmr0, rtmr1, rtmr2, rtmr3] = TDX_QUOTE_RTMR_OFFSETS.map(measurement);

  return {
    measurements: {
      mrtd: measurement(TDX_QUOTE_MRTD_OFFSET),
      rtmr0,
      rtmr1,
      rtmr2,
      rtmr3,
    },
    reportData: Buffer.from(
      quote.subarray(
        TDX_QUOTE_REPORT_DATA_OFFSET,
        TDX_QUOTE_REPORT_DATA_OFFSET + REPORT_DATA_LENGTH,
      ),
    ),
  };
}
